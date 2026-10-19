/*
 * SNode.C SSO/MFA Identity Provider
 * Copyright (C) Jan Nicolas Eberwein 2025/2026 — Master Thesis
 *
 * Identity Provider implementing:
 *   - OAuth2 Authorization Code Flow with PKCE (RFC 7636)
 *   - TOTP Multi-Factor Authentication (RFC 6238)
 *   - JWT access tokens (RS256)
 *   - PBKDF2-HMAC-SHA256 password hashing (with SHA-256 migration)
 *   - AES-256-GCM encryption for TOTP secrets at rest
 *   - Sliding-window rate limiting for login/MFA endpoints
 *   - Browser-bound login transactions and live-session authorization
 *   - Federated login (Google OIDC)
 *   - User registration, login, MFA enrollment
 *   - Password reset via token (email-capable)
 *   - SQLite backend (MariaDB-free, router-compatible)
 */

#include "auth/IdpMiddleware.h"

#include "Log.h"
#include "auth/AuthStore.h"
#include "auth/HttpEncode.h"
#include "auth/HttpExchange.h"
#include "auth/JwtSigner.h"
#include "auth/PasswordHasher.h"
#include "auth/QrCodeGenerator.h"
#include "auth/RateLimiter.h"
#include "auth/SecretEncryptor.h"
#include "auth/Totp.h"
#include "database/sqlite/SqliteDatabase.h"
#include "web/http/http_utils.h"

#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <map>
#include <memory>
#include <nlohmann/json.hpp>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

using namespace snodec;
using namespace snodec::auth;
using namespace snodec::database::sqlite;
using json = nlohmann::json;

#include <cstdio>

namespace {
    class IdpState : public std::enable_shared_from_this<IdpState> {
    public:
        explicit IdpState(IdpConfig input)
            : config(validate(std::move(input)))
            , db(config.databasePath)
            , store(db, config.clients)
            , jwtSigner(config.issuer, loadPrivateKey(config.privateKeyPath))
            , jwksDocument(jwtSigner.jwks()) {
            db.initSchema();
            store.migrateTotp(config.totpKeyPath);
        }

        static IdpConfig validate(IdpConfig input) {
            require(!input.issuer.empty() && input.issuer.back() != '/' && endpoint(input.issuer).origin == input.issuer,
                    "IDP issuer must be an origin without a trailing slash");
            require(!input.databasePath.empty() && !input.privateKeyPath.empty() && !input.totpKeyPath.empty(),
                    "IDP database, private key and TOTP key paths are required");
            return input;
        }

        const IdpConfig config;
        SqliteDatabase db;
        AuthStore store;
        JwtSigner jwtSigner;
        const std::string jwksDocument;
        RateLimiter loginLimiter{5, 60};
        RateLimiter mfaLimiter{5, 60};
        const std::chrono::steady_clock::time_point startTime = std::chrono::steady_clock::now();

        std::string formatUptime() {
            auto diff = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - startTime).count();
            auto days = diff / 86400;
            auto hours = (diff % 86400) / 3600;

            std::string res;
            if (days > 0) {
                res += std::to_string(days) + "d ";
            }
            if (hours > 0 || days > 0) {
                res += std::to_string(hours) + "h ";
            }
            res += std::to_string((diff % 3600) / 60) + "m " + std::to_string(diff % 60) + "s";
            return res;
        }

        // ============================================================================
        // Utility — private key loader
        // ============================================================================

        std::string loadPrivateKey(const std::string& path) {
            std::ifstream file(path);
            require(file.good(), "Cannot open configured private key");
            return {std::istreambuf_iterator<char>(file), {}};
        }

        // ============================================================================
        // Utility — cryptography
        // ============================================================================

        // Verify password, supporting both PBKDF2 and legacy SHA-256 formats.
        // If legacy format is verified, returns the user ID for migration.
        bool verifyPasswordAny(const std::string& pw, const std::string& storedHash, const std::string& salt, bool& needsMigration) {
            needsMigration = false;
            bool verified = false;
            if (storedHash.rfind("$pbkdf2-sha256$", 0) == 0) {
                verified = PasswordHasher::verifyPassword(pw, storedHash);
            } else if (PasswordHasher::isLegacyHash(storedHash)) {
                verified = PasswordHasher::verifyLegacy(pw, storedHash, salt);
                needsMigration = verified;
            }
            return verified;
        }

        // Migrate a legacy SHA-256 hash to PBKDF2 in the database
        void migratePasswordHash(const std::string& userId, const std::string& pw) {
            std::string newHash = PasswordHasher::hashPassword(pw);
            std::string err;
            db.exec("UPDATE user SET password_hash=?, password_salt='' WHERE id=?", {newHash, userId}, &err);
            if (err.empty()) {
                snode::log::application().info() << "Migrated password hash to PBKDF2 for user ID " << userId;
            }
        }

        // --- TOTP secret encryption helpers ---

        std::string encryptTotpSecret(const std::string& secret) {
            require(!config.totpKeyPath.empty(), "TOTP encryption key required");
            return SecretEncryptor::encrypt(secret, config.totpKeyPath);
        }

        std::string decryptTotpSecret(const std::string& secret) {
            require(!config.totpKeyPath.empty() && SecretEncryptor::isEncrypted(secret), "Encrypted TOTP secret required");
            return SecretEncryptor::decrypt(secret, config.totpKeyPath);
        }

        std::string urlDecode(const std::string& s) {
            std::string r;
            r.reserve(s.size());
            for (size_t i = 0; i < s.size(); ++i) {
                if (s[i] == '%' && i + 2 < s.size() && std::isxdigit(static_cast<unsigned char>(s[i + 1])) &&
                    std::isxdigit(static_cast<unsigned char>(s[i + 2]))) {
                    r += static_cast<char>(std::strtol(s.substr(i + 1, 2).c_str(), nullptr, 16));
                    i += 2;
                } else if (s[i] == '+') {
                    r += ' ';
                } else {
                    r += s[i];
                }
            }
            return r;
        }

        std::map<std::string, std::string> parseBody(const std::vector<char>& body) {
            std::string raw(body.begin(), body.end());
            std::map<std::string, std::string> params;
            std::istringstream ss(raw);
            std::string tok;
            while (std::getline(ss, tok, '&')) {
                auto pos = tok.find('=');
                if (pos != std::string::npos) {
                    params[urlDecode(tok.substr(0, pos))] = urlDecode(tok.substr(pos + 1));
                }
            }
            return params;
        }

        // ============================================================================
        // Password-reset credentials leave the process only through configured mail delivery.
        void sendPasswordResetLink(const std::string& email, const std::string& resetUrl) {
            const auto& command = config.smtpCommand;
            require(!command.empty() && email.find_first_of("\r\n") == std::string::npos, "Mail delivery unavailable");
            const std::string body = "To: " + email + "\r\nSubject: Password reset\r\n\r\n" + resetUrl + "\r\n";
            FILE* pipe = popen(command.c_str(), "w");
            require(pipe != nullptr, "Mail delivery unavailable");
            const bool written = fwrite(body.data(), 1, body.size(), pipe) == body.size();
            const int result = pclose(pipe);
            require(written && result == 0, "Mail delivery failed");
        }

        std::string html(const std::string& input) {
            std::string output;
            for (char c : input) {
                switch (c) {
                    case '&':
                        output += "&amp;";
                        break;
                    case '<':
                        output += "&lt;";
                        break;
                    case '>':
                        output += "&gt;";
                        break;
                    case '\"':
                        output += "&quot;";
                        break;
                    case '\'':
                        output += "&#39;";
                        break;
                    default:
                        output += c;
                }
            }
            return output;
        }

        static constexpr const char* PAGE_CSS = R"(
:root {
    --bg-color: #f5f8f7; --text-color: #142c3b; --card-bg: #ffffff;
    --card-border: #dce5e6; --input-bg: #ffffff; --input-border: #bdcccf;
    --input-focus: #086b60; --btn-bg: #142c3b; --btn-hover: #086b60;
    --btn-text: #ffffff; --link-color: #086b60; --text-muted: #536875;
    --header-bg: #f5f8f7; --header-border: #dce5e6;
}
[data-theme="dark"] {
    color-scheme: dark;
    --bg-color: #101d25; --text-color: #edf5f4; --card-bg: #172a35;
    --card-border: #304753; --input-bg: #12232d; --input-border: #4a6370;
    --input-focus: #79d6c3; --btn-bg: #126d61; --btn-hover: #188676;
    --btn-text: #ffffff; --link-color: #8ddcca; --text-muted: #adc0c9;
    --header-bg: #101d25; --header-border: #304753;
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
    font-family: Inter, system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    background: var(--bg-color); color: var(--text-color); line-height: 1.6;
    min-height: 100vh; display: flex; flex-direction: column; -webkit-font-smoothing: antialiased;
}
a { color: var(--link-color); text-underline-offset: 4px; }
a:hover { text-decoration-thickness: 2px; }
button, input { font: inherit; }
a:focus-visible, button:focus-visible { outline: 3px solid var(--input-focus); outline-offset: 4px; }
header {
    border-bottom: 1px solid var(--header-border); background: var(--header-bg);
    display: flex; justify-content: space-between; align-items: center; gap: 24px; padding: 24px 40px;
}
.header-logo { font-weight: 750; font-size: 1.05rem; letter-spacing: -.3px; color: var(--text-color); text-decoration: none; display: flex; align-items: center; gap: 10px; }
.header-nav { display: flex; align-items: center; gap: 24px; flex-wrap: wrap; }
.header-nav a { color: var(--text-color); text-decoration: none; font-size: .85rem; font-weight: 550; }
.header-nav a:hover { color: var(--link-color); }
.header-top { display: contents; }
.burger-menu { display: none; background: none; border: none; cursor: pointer; color: var(--text-color); padding: 4px; }
.burger-menu svg { width: 28px; height: 28px; fill: currentColor; }
.mobile-user { display: none; }
.desktop-user { display: flex; }
main { flex: 1; display: flex; flex-direction: column; justify-content: center; align-items: center; padding: 56px 24px; }
.card { background: var(--card-bg); border: 1px solid var(--card-border); border-radius: 18px; padding: 38px; width: 100%; max-width: 460px; box-shadow: 0 18px 50px #142c3b08; }
h1 { font-size: 1.85rem; line-height: 1.2; letter-spacing: -.8px; font-weight: 650; margin-bottom: 24px; text-wrap: balance; }
h2, h3 { line-height: 1.4; }
p { color: var(--text-muted); line-height: 1.7; }
.card > p { margin: 12px 0; overflow-wrap: anywhere; }
.card > p:empty { display: none; }
.card > .form-error:not(:empty) { padding: 12px 14px; background: #c63c3312; border-left: 3px solid #c63c33; color: var(--text-color); border-radius: 5px; }
.card > a { font-size: .875rem; }
.card img { display: block; max-width: 100%; height: auto; margin: 20px auto; border-radius: 8px; }
.subtitle { color: var(--text-muted); font-size: .95rem; margin-bottom: 26px; }
.card form { margin: 20px 0; }
.form-group { margin-bottom: 20px; }
label { display: block; font-size: .85rem; font-weight: 600; color: var(--text-color); margin-bottom: 16px; }
input:not([type]), input[type="text"], input[type="password"], input[type="email"], input[type="number"] {
    display: block; width: 100%; min-height: 46px; margin-top: 7px; padding: 11px 13px;
    background: var(--input-bg); border: 1px solid var(--input-border); border-radius: 8px; color: var(--text-color); font-size: 1rem;
}
input:focus { outline: 2px solid var(--input-focus); outline-offset: 2px; border-color: var(--input-focus); }
input[name="code"] { letter-spacing: .3em; text-align: center; font-size: 1.35rem; margin-bottom: 20px; }
input[type="checkbox"] { width: 17px; height: 17px; margin-right: 9px; vertical-align: middle; accent-color: var(--link-color); }
label:has(input[type="checkbox"]), .checkbox-group { display: flex; align-items: center; gap: 4px; font-weight: 450; line-height: 1.5; }
.checkbox-group { margin-bottom: 24px; }
.checkbox-group label { margin: 0; }
.btn, .card form button {
    display: block; width: 100%; padding: 13px 18px; background: var(--btn-bg); color: var(--btn-text);
    border: 1px solid transparent; border-radius: 8px; text-align: center; font-size: .925rem; font-weight: 650; cursor: pointer; text-decoration: none;
}
.btn:hover, .card form button:hover { background: var(--btn-hover); }
.btn-secondary, .card form[action^="/auth/enroll/totp/skip"] button { background: transparent; color: var(--text-color); border-color: var(--input-border); }
.btn-secondary:hover, .card form[action^="/auth/enroll/totp/skip"] button:hover { background: var(--bg-color); }
.btn-red, .card form .btn-red, .logout-btn { background: #b52e30; color: #fff; }
.btn-red:hover, .card form .btn-red:hover, .logout-btn:hover { background: #962428; }
.error-box, .info-box, .success-box { padding: 16px; border-radius: 10px; margin-bottom: 24px; font-size: .9rem; line-height: 1.5; display: flex; align-items: center; gap: 12px; }
.error-box { background: #c63c3312; color: var(--text-color); border: 1px solid #c63c3370; }
.info-box { background: #3088b012; color: var(--text-color); border: 1px solid #3088b070; }
.success-box { background: #16876a12; color: var(--text-color); border: 1px solid #16876a70; }
.links { text-align: center; margin-top: 24px; font-size: .9rem; }
.links a { color: var(--link-color); }
.theme-switch { background: transparent; border: none; cursor: pointer; display: flex; align-items: center; justify-content: center; color: var(--text-color); padding: 8px; border-radius: 8px; }
.theme-switch svg { width: 20px; height: 20px; fill: currentColor; }
.divider { height: 1px; background: var(--card-border); margin: 24px 0; }
.logout-btn { border: none; cursor: pointer; font-weight: 600; font-size: .85rem; padding: 8px 16px; border-radius: 8px; }
.dashboard-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 20px; width: 100%; max-width: 1200px; margin: auto; align-items: stretch; }
.stat-card { background: var(--card-bg); border: 1px solid var(--card-border); border-radius: 16px; padding: 24px; display: flex; flex-direction: column; }
.stat-value { font-size: 2.2rem; font-weight: 650; margin-top: 12px; color: var(--text-color); }
.stat-label { font-size: .75rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 1px; font-weight: 600; }
.logo-icon { width: 48px; height: 48px; margin: 0 auto 20px; display: block; fill: var(--link-color); }
.clickable-card { cursor: pointer; }
.clickable-card:hover { border-color: var(--link-color); }
footer { padding: 24px; color: var(--text-muted); font-size: .75rem; border-top: 1px solid var(--header-border); }
.footer-content { display: flex; justify-content: center; gap: 12px; align-items: center; flex-wrap: wrap; }
.footer-content a { color: var(--text-muted); text-decoration: none; }
.footer-content a:hover { color: var(--link-color); }
@media (min-width: 600px) { .span-2 { grid-column: span 2; } }
@media (max-width: 600px) {
    header { padding: 20px; flex-direction: column; gap: 12px; }
    .header-top { display: flex; justify-content: space-between; align-items: center; width: 100%; }
    .header-logo { font-size: .9rem; gap: 7px; }
    .mobile-user { display: block; }
    .burger-menu { display: block; }
    .header-nav { display: none; flex-direction: column; gap: 16px; align-items: stretch; width: 100%; padding-top: 16px; }
    .header-nav.open { display: flex; }
    .header-nav a, .header-nav form { width: 100%; }
    .theme-switch { align-self: flex-start; }
    .desktop-user { display: none !important; }
    main { padding: 32px 16px; }
    .card { padding: 28px 24px; }
    h1 { font-size: 1.6rem; }
    .dashboard-grid { grid-template-columns: minmax(0, 1fr); }
    .span-2 { grid-column: span 1; }
    .footer-content { flex-direction: column; gap: 6px; }
    .footer-divider, .desktop-only { display: none; }
}
)";

        static constexpr const char* PAGE_JS = R"(
<script>
const sunIcon = `<svg viewBox="0 0 24 24"><path d="M12 2.25a.75.75 0 01.75.75v2.25a.75.75 0 01-1.5 0V3a.75.75 0 01.75-.75zM7.5 12a4.5 4.5 0 119 0 4.5 4.5 0 01-9 0zM18.894 6.166a.75.75 0 00-1.06-1.06l-1.591 1.59a.75.75 0 101.06 1.061l1.591-1.59zM21.75 12a.75.75 0 01-.75.75h-2.25a.75.75 0 010-1.5H21a.75.75 0 01.75.75zM17.834 18.894a.75.75 0 001.06-1.06l-1.59-1.591a.75.75 0 10-1.061 1.06l1.59 1.591zM12 18.75a.75.75 0 01.75.75V21a.75.75 0 01-1.5 0v-1.5a.75.75 0 01.75-.75zM6.166 17.834a.75.75 0 00-1.06 1.06l1.59 1.591a.75.75 0 101.06-1.061l-1.59-1.59zM4.5 12a.75.75 0 01-.75-.75H1.5a.75.75 0 000 1.5h2.25a.75.75 0 01.75-.75zM6.166 6.166a.75.75 0 011.06-1.06l1.59 1.59a.75.75 0 01-1.06 1.061l-1.59-1.59z"></path></svg>`;
const moonIcon = `<svg viewBox="0 0 24 24"><path d="M9.528 1.718a.75.75 0 01.162.819A8.97 8.97 0 009 6a9 9 0 009 9 8.97 8.97 0 003.463-.69.75.75 0 01.981.98 10.503 10.503 0 01-9.694 6.46c-5.799 0-10.5-4.701-10.5-10.5 0-4.368 2.667-8.112 6.46-9.694a.75.75 0 01.818.162z"></path></svg>`;
function toggleTheme() {
    const isDark = document.body.getAttribute('data-theme') === 'dark';
    const newTheme = isDark ? 'light' : 'dark';
    document.body.setAttribute('data-theme', newTheme);
    localStorage.setItem('theme', newTheme);
    document.getElementById('theme-icon').innerHTML = newTheme === 'dark' ? sunIcon : moonIcon;
}
window.onload = () => {
    const saved = localStorage.getItem('theme') || (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
    document.body.setAttribute('data-theme', saved);
    document.getElementById('theme-icon').innerHTML = saved === 'dark' ? sunIcon : moonIcon;
};
</script>
)";

        static constexpr const char* ICONS = R"(
<svg style="display:none;">
<symbol id="icon-lock" viewBox="0 0 24 24"><path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zM9 6c0-1.66 1.34-3 3-3s3 1.34 3 3v2H9V6zm9 14H6V10h12v10zm-6-3c1.1 0 2-.9 2-2s-.9-2-2-2-2 .9-2 2 .9 2 2 2z"/></symbol>
<symbol id="icon-user" viewBox="0 0 24 24"><path d="M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z"/></symbol>
<symbol id="icon-settings" viewBox="0 0 24 24"><path d="M19.14,12.94c0.04-0.3,0.06-0.61,0.06-0.94c0-0.32-0.02-0.64-0.06-0.94l2.03-1.58c0.18-0.14,0.23-0.41,0.12-0.61 l-1.92-3.32c-0.12-0.22-0.37-0.29-0.59-0.22l-2.39,0.96c-0.5-0.38-1.03-0.7-1.62-0.94L14.4,2.81c-0.04-0.24-0.24-0.41-0.48-0.41 h-3.84c-0.24,0-0.43,0.17-0.47,0.41L9.25,5.35C8.66,5.59,8.12,5.92,7.63,6.29L5.24,5.33c-0.22-0.08-0.47,0-0.59,0.22L2.73,8.87 C2.62,9.08,2.66,9.34,2.86,9.48l2.03,1.58C4.84,11.36,4.8,11.69,4.8,12s0.02,0.64,0.06,0.94l-2.03,1.58 c-0.18,0.14-0.23,0.41-0.12,0.61l1.92,3.32c0.12,0.22,0.37,0.29,0.59,0.22l2.39-0.96c0.5,0.38,1.03,0.7,1.62,0.94l0.36,2.54 c0.05,0.24,0.24,0.41,0.48,0.41h3.84c0.24,0,0.43-0.17,0.47-0.41l0.36-2.54c0.59-0.24,1.13-0.56,1.62-0.94l2.39,0.96 c0.22,0.08,0.47,0,0.59-0.22l1.92-3.32c0.12-0.22,0.07-0.49-0.12-0.61L19.14,12.94z M12,15.6c-1.98,0-3.6-1.62-3.6-3.6 s1.62-3.6,3.6-3.6s3.6,1.62,3.6,3.6S13.98,15.6,12,15.6z"/></symbol>
<symbol id="icon-shield" viewBox="0 0 24 24"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z"/></symbol>
<symbol id="icon-rocket" viewBox="0 0 24 24"><path d="M13.13 22.19l-1.63-3.83c3.61-.58 7.09-2.58 9.55-5.95l-7.92 9.78zm-2.26-10.3c1.38 0 2.5-1.12 2.5-2.5s-1.12-2.5-2.5-2.5-2.5 1.12-2.5 2.5 1.12 2.5 2.5 2.5zm11.39-9.87c-1.39-.42-5.45-.63-10.22 3.01L8.9 8.16l-3.33-1.07-3.9 3.89 4.16 1.86-1.94 4.54 1.34 1.34 2.8-6.52 1.86 4.15 3.9-3.9-1.07-3.32 3.12-3.13c3.65-4.78 3.44-8.84 3.02-10.23z"/></symbol>
</svg>
)";

        std::string formatUserDisplayName(const std::string& username, const std::string& email) {
            std::string lower = username;
            for (auto& c : lower) {
                c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            }
            bool isPlaceholder = (lower == "google_user" || lower == "google user" || lower == "googleuser" ||
                                  lower.rfind("user_", 0) == 0 || lower.rfind("google_", 0) == 0);
            return email.empty() ? username : (username.empty() || isPlaceholder) ? email : username + " (" + email + ")";
        }

        struct Navigation {
            std::string clientId, target;
            std::string link(const std::string& path) const {
                return target.empty() ? path
                                      : path + (path.find('?') == std::string::npos ? "?" : "&") +
                                            formEncode({{"client_id", clientId}, {"return", target}});
            }
        };

        std::string buildPage(const Navigation& navigation,
                              const std::string& raw_title,
                              const std::string& body,
                              bool isAuthenticated = false,
                              const std::string& raw_username = "") {
            const auto title = html(raw_title);
            const auto username = html(raw_username);

            std::string mobileUsername = username;
            size_t paren = mobileUsername.find(" (");
            if (paren != std::string::npos) {
                mobileUsername = mobileUsername.substr(0, paren);
            }

            std::string accountBtn = "";
            if (isAuthenticated && !username.empty()) {
                accountBtn = "<a href=\"" + html(navigation.link("/settings")) +
                             "\" class=\"desktop-user\" style=\"background:var(--btn-bg);color:#fff;padding:6px "
                             "14px;border-radius:20px;font-weight:600;align-items:center;gap:6px;text-decoration:none;\">"
                             "<svg width=\"16\" height=\"16\" fill=\"currentColor\"><use href=\"#icon-user\"/></svg>" +
                             username + "</a>";
            }

            const auto& webAppUrl = navigation.target;
            std::string protectedAppStr = "";
            if (!webAppUrl.empty()) {
                protectedAppStr = "<a href=\"" + html(webAppUrl) + "\" style=\"color:#3b82f6; font-weight:600;\">Back to application</a>";
            }

            std::string navLinks = isAuthenticated ? accountBtn + "<a href=\"" + html(navigation.link("/dashboard")) +
                                                         "\">Dashboard</a>"
                                                         "<a href=\"" +
                                                         html(navigation.link("/settings")) + "\">Settings</a>" + protectedAppStr +
                                                         "<form method=\"POST\" action=\"" + html(navigation.link("/auth/logout")) +
                                                         "\" style=\"display:inline;margin:0;\">"
                                                         "<button type=\"submit\" class=\"logout-btn\">Sign Out</button></form>"
                                                   : "<a href=\"" + html(navigation.link("/auth/login")) + "\">Sign In</a><a href=\"" +
                                                         html(navigation.link("/auth/register")) + "\">Create Account</a>";

            return "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n"
                   "<meta charset=\"UTF-8\">\n"
                   "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1.0,viewport-fit=cover\">\n"
                   "<meta name=\"description\" content=\"SNode.C Central Identity Provider. Secure OAuth2 & TOTP MFA.\">\n"
                   "<meta name=\"theme-color\" content=\"#142c3b\">\n"
                   "<link rel=\"icon\" href=\"data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 24 24%22 "
                   "fill=%22%230066cc%22><path d=%22M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 "
                   "2-.9 2-2V10c0-1.1-.9-2-2-2zM9 6c0-1.66 1.34-3 3-3s3 1.34 3 3v2H9V6zm9 14H6V10h12v10zm-6-3c1.1 0 2-.9 2-2s-.9-2-2-2-2 "
                   ".9-2 2 .9 2 2 2z%22/></svg>\">\n"
                   "<title>" +
                   title +
                   " — SNode.C IdP</title>\n"
                   "<style>" +
                   PAGE_CSS + "</style>\n" + PAGE_JS + "</head>\n<body>\n" + ICONS +
                   "<header>\n"
                   "<div class=\"header-top\">\n"
                   "  <div style=\"display:flex; flex-direction:column; gap:4px;\">\n"
                   "    <a href=\"" +
                   html(navigation.link("/")) +
                   "\" class=\"header-logo\"><svg width=\"24\" height=\"24\" viewBox=\"0 0 24 24\" "
                   "fill=\"var(--btn-bg)\"><path d=\"M12 "
                   "2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5\"/></svg> SNode.C <span style=\"font-weight:400; "
                   "opacity:0.7;\">Identity Provider</span></a>\n" +
                   (isAuthenticated && !username.empty() ? "    <div class=\"mobile-user\" style=\"font-size:0.85rem; "
                                                           "color:var(--text-muted); font-weight:500; margin-left:32px;\">" +
                                                               mobileUsername + "</div>\n"
                                                         : "") +
                   "  </div>\n"
                   "  <button class=\"burger-menu\" aria-label=\"Toggle navigation\" "
                   "onclick=\"document.getElementById('nav-menu').classList.toggle('open');\" "
                   "style=\"margin-top:2px;\">\n"
                   "    <svg viewBox=\"0 0 24 24\"><path d=\"M3 18h18v-2H3v2zm0-5h18v-2H3v2zm0-7v2h18V6H3z\"/></svg>\n"
                   "  </button>\n"
                   "</div>\n"
                   "<nav class=\"header-nav\" id=\"nav-menu\">\n" +
                   navLinks +
                   "<button class=\"theme-switch\" aria-label=\"Toggle color theme\" onclick=\"toggleTheme()\" "
                   "id=\"theme-icon\"></button>\n"
                   "</nav>\n</header>\n"
                   "<main>\n" +
                   body +
                   "\n</main>\n"
                   "<footer><div class=\"footer-content\">\n"
                   "  <span class=\"footer-copyright\">&copy; 2026 "
                   "<a href=\"https://www.janeberwein.at\" target=\"_blank\" rel=\"noopener noreferrer\">Jan Eberwein</a> &amp; "
                   "<a href=\"https://github.com/VolkerChristian\" target=\"_blank\" rel=\"noopener noreferrer\">Volker "
                   "Christian</a></span>\n"
                   "  <span class=\"footer-divider\">|</span>\n"
                   "  <span class=\"footer-links\"><a href=\"https://opensource.org/licenses/MIT\" target=\"_blank\" rel=\"noopener "
                   "noreferrer\">MIT License</a></span>\n"
                   "</div></footer>\n"
                   "</body>\n</html>\n";
        }

        // ============================================================================
        // HTML page builders — each is a pure function, no side-effects
        // ============================================================================

        std::string loginPage(const Navigation& navigation, const std::string& transaction, const std::string& error = "") {
            return buildPage(
                navigation,
                "Sign in",
                "<div class=\"card\"><h1>Sign in</h1><p class=\"form-error\" role=\"alert\">" + html(error) +
                    "</p><form method=\"post\" action=\"" + html(navigation.link("/auth/login")) + "\">" +
                    "<input type=\"hidden\" name=\"transaction\" value=\"" + html(transaction) +
                    "\"><label>Username<input name=\"username\" required></label>"
                    "<label>Password<input type=\"password\" name=\"password\" required></label><button>Sign in</button></form>"
                    "<a href=\"" +
                    html(navigation.link("/auth/register")) + "\">Register</a> · <a href=\"" +
                    html(navigation.link("/auth/forgot-password")) +
                    "\">Reset password</a>"
                    "<p><a href=\"" +
                    html(navigation.link("/auth/federated/google")) + "\">Sign in with Google</a></p></div>");
        }

        std::string registerPage(const Navigation& navigation, const std::string& transaction, const std::string& error = "") {
            return buildPage(
                navigation,
                "Register",
                "<div class=\"card\"><h1>Register</h1><p class=\"form-error\" role=\"alert\">" + html(error) +
                    "</p><form method=\"post\" action=\"" + html(navigation.link("/auth/register")) + "\">" +
                    "<input type=\"hidden\" name=\"transaction\" value=\"" + html(transaction) +
                    "\"><label>Username<input name=\"username\" required></label>"
                    "<label>Email<input type=\"email\" name=\"email\" required></label>"
                    "<label>Password<input type=\"password\" name=\"password\" required></label>"
                    "<label>Confirm password<input type=\"password\" name=\"confirm_password\" required></label>"
                    "<label><input type=\"checkbox\" name=\"enable_mfa\" value=\"1\" checked>Enable two-factor authentication</label>"
                    "<button>Register</button></form></div>");
        }

        std::string mfaPage(const Navigation& navigation, const std::string& transaction, const std::string& error = "") {
            return buildPage(navigation,
                             "Two-factor authentication",
                             "<div class=\"card\"><h1>Authenticator code</h1><p class=\"form-error\" role=\"alert\">" + html(error) +
                                 "</p><form method=\"post\" action=\"" + html(navigation.link("/auth/mfa")) + "\">" +
                                 "<input type=\"hidden\" name=\"transaction\" value=\"" + html(transaction) +
                                 "\"><input name=\"code\" aria-label=\"Authenticator code\" inputmode=\"numeric\" "
                                 "autocomplete=\"one-time-code\" pattern=\"[0-9]{6}\" required>"
                                 "<button>Verify</button></form></div>");
        }

        std::string enrollTotpPage(const Navigation& navigation,
                                   const std::string& secret,
                                   const std::string& uri,
                                   const std::string& transaction,
                                   bool required) {
            return buildPage(navigation,
                             "Enable two-factor authentication",
                             "<div class=\"card\"><h1>Set up your authenticator</h1>"
                             "<img alt=\"Authenticator QR code\" src=\"" +
                                 QrCodeGenerator::generateDataUri(uri) + "\"><p>" + html(secret) + "</p><form method=\"post\" action=\"" +
                                 html(navigation.link("/auth/enroll/totp/verify")) + "\">" +
                                 "<input type=\"hidden\" name=\"transaction\" value=\"" + html(transaction) +
                                 "\"><input name=\"code\" aria-label=\"Authenticator code\" inputmode=\"numeric\" "
                                 "autocomplete=\"one-time-code\" pattern=\"[0-9]{6}\" required>"
                                 "<button>Activate</button></form>" +
                                 (required ? "<p>This application requires two-factor authentication.</p>"
                                           : "<form method=\"post\" action=\"" + html(navigation.link("/auth/enroll/totp/skip")) +
                                                 "\">"
                                                 "<input type=\"hidden\" name=\"transaction\" value=\"" +
                                                 html(transaction) + "\"><button>Skip</button></form>") +
                                 "</div>");
        }

        std::string landingPage(const Navigation& navigation) {
            std::string body = "<div class=\"card\" style=\"text-align:center;\">\n"
                               "<svg class=\"logo-icon\"><use href=\"#icon-rocket\"/></svg>\n"
                               "<h1>SNode.C</h1>\n"
                               "<p class=\"subtitle\">Identity Provider</p>\n"
                               "<a href=\"" +
                               html(navigation.link("/auth/login")) +
                               "\" class=\"btn\" style=\"margin-bottom:12px;\">Sign In</a>\n"
                               "<a href=\"" +
                               html(navigation.link("/auth/register")) +
                               "\" class=\"btn btn-secondary\">Create Account</a>\n"
                               "</div>\n";
            return buildPage(navigation, "Welcome", body, false);
        }

        std::string dashboardPage(const Navigation& navigation,
                                  const std::string& raw_username,
                                  int users,
                                  int sessions,
                                  int pendingTokens,
                                  int mfaUsers,
                                  const std::string& raw_uptime,
                                  bool mfaEnabled) {
            const auto username = html(raw_username);
            const auto uptime = html(raw_uptime);

            std::string alertBox = "";
            if (!mfaEnabled) {
                alertBox = "<div style=\"background:rgba(249,115,22,0.1); border:1.5px solid rgba(249,115,22,0.35); "
                           "border-radius:12px; padding:16px; margin-bottom:28px; display:flex; align-items:center; gap:14px; "
                           "color:#ffedd5; font-size:0.92rem; text-align:left;\">"
                           "<svg width=\"22\" height=\"22\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"#f97316\" stroke-width=\"2\" "
                           "style=\"flex-shrink:0;\">"
                           "<path d=\"M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z\"/>"
                           "<line x1=\"12\" y1=\"9\" x2=\"12\" y2=\"13\"/>"
                           "<line x1=\"12\" y1=\"17\" x2=\"12.01\" y2=\"17\"/>"
                           "</svg>"
                           "<div><strong>Multi-Factor Authentication (MFA) is not active.</strong> "
                           "Your account is currently secured with a single factor. To add a second factor, please "
                           "<a href=\"" +
                           html(navigation.link("/settings")) +
                           "\" style=\"color:#fb923c; text-decoration:underline; font-weight:600;\">configure MFA in "
                           "your Account Settings</a>.</div>"
                           "</div>";
            }

            std::string body =
                "<div style=\"max-width: 1200px; margin: 0 auto; width: 100%;\">\n" + alertBox +
                "</div>\n"
                "<div class=\"dashboard-grid\">\n"
                "  <div class=\"stat-card span-2\" style=\"background: linear-gradient(135deg, var(--btn-bg), #004499); color: white;\">\n"
                "    <span class=\"stat-label\" style=\"color: rgba(255,255,255,0.8);\">System Uptime</span>\n"
                "    <span class=\"stat-value\" style=\"color: white;\">" +
                uptime +
                "</span>\n"
                "    <div style=\"margin-top:24px; height:60px; display:flex; align-items:flex-end; gap:8px;\">"
                "      <div style=\"flex:1; height:40%; background:rgba(255,255,255,0.3); border-radius:4px;\"></div>"
                "      <div style=\"flex:1; height:70%; background:rgba(255,255,255,0.4); border-radius:4px;\"></div>"
                "      <div style=\"flex:1; height:50%; background:rgba(255,255,255,0.5); border-radius:4px;\"></div>"
                "      <div style=\"flex:1; height:90%; background:rgba(255,255,255,0.6); border-radius:4px;\"></div>"
                "      <div style=\"flex:1; height:60%; background:rgba(255,255,255,0.7); border-radius:4px;\"></div>"
                "      <div style=\"flex:1; height:80%; background:rgba(255,255,255,0.8); border-radius:4px;\"></div>"
                "      <div style=\"flex:1; height:100%; background:white; border-radius:4px; position:relative;\">"
                "        <div style=\"position:absolute; top:-20px; right:-10px; width:8px; height:8px; background:#34c759; "
                "border-radius:50%; "
                "box-shadow: 0 0 8px #34c759;\"></div>"
                "      </div>"
                "    </div>"
                "  </div>\n"
                "  <div class=\"stat-card\">\n"
                "    <span class=\"stat-label\">Registered Users</span>\n"
                "    <span class=\"stat-value\">" +
                std::to_string(users) +
                "</span>\n"
                "  </div>\n"
                "  <div class=\"stat-card\">\n"
                "    <span class=\"stat-label\">Active Sessions</span>\n"
                "    <span class=\"stat-value\">" +
                std::to_string(sessions) +
                "</span>\n"
                "  </div>\n"
                "  <div class=\"stat-card\">\n"
                "    <span class=\"stat-label\">MFA Enrolled Users</span>\n"
                "    <span class=\"stat-value\">" +
                std::to_string(mfaUsers) +
                "</span>\n"
                "  </div>\n"
                "  <div class=\"stat-card\">\n"
                "    <span class=\"stat-label\">Pending Auth Codes</span>\n"
                "    <span class=\"stat-value\">" +
                std::to_string(pendingTokens) +
                "</span>\n"
                "  </div>\n"
                "  <div class=\"stat-card span-2\">\n"
                "    <span class=\"stat-label\">IdP configuration</span>\n"
                "    <span class=\"stat-value\" style=\"font-size:1.5rem; margin-top:8px;\">Issuer: " +
                config.issuer +
                "</span>\n"
                "    <div style=\"display:flex; justify-content:space-between; margin-top:16px; color:var(--text-muted); "
                "font-size:0.9rem;\">"
                "      <span>Federated Logins: Google</span>"
                "      <span style=\"color:#28a745;\">● Secured</span>"
                "    </div>"
                "  </div>\n"
                "  <a href=\"" +
                html(navigation.link("/settings")) +
                "\" class=\"stat-card clickable-card span-2\" style=\"text-decoration:none; display:flex; "
                "flex-direction:row; "
                "justify-content:space-between; align-items:center;\">\n"
                "    <div style=\"display:flex; flex-direction:column;\">\n"
                "      <span class=\"stat-label\">Settings & Security</span>\n"
                "      <span class=\"stat-value\" style=\"font-size:1.4rem; margin-top:6px;\">Manage Account</span>\n"
                "    </div>\n"
                "    <div style=\"display:flex; align-items:center; color:var(--text-muted);\">\n"
                "      <svg width=\"24\" height=\"24\" fill=\"currentColor\" style=\"margin-right:8px;\"><use "
                "href=\"#icon-settings\"/></svg>\n"
                "      <svg width=\"16\" height=\"16\" viewBox=\"0 0 24 24\" fill=\"currentColor\"><path d=\"M8.59 16.59L13.17 12 8.59 "
                "7.41 10 6l6 "
                "6-6 6-1.41-1.41z\"/></svg>\n"
                "    </div>\n"
                "  </a>\n"
                "</div>\n";
            return buildPage(navigation, "Dashboard", body, true, raw_username);
        }

        std::string settingsPage(const Navigation& navigation,
                                 const std::string& raw_username,
                                 const std::string& raw_email,
                                 bool mfaEnabled,
                                 bool isFederated,
                                 const std::string& raw_message = "",
                                 bool isError = false) {
            const auto username = html(raw_username);
            const auto email = html(raw_email);
            const auto message = html(raw_message);

            const std::string cancelBtn =
                "<a href=\"" + html(navigation.link("/settings")) + "\" class=\"btn btn-secondary\" style=\"flex:1;\">Cancel</a>";

            std::string mfaStatus =
                mfaEnabled
                    ? "<div style=\"display:flex; align-items:center; justify-content:space-between; padding:16px; "
                      "background:rgba(52,199,89,0.05); border:1px solid rgba(52,199,89,0.2); border-radius:12px; margin-top:12px;\">"
                      "  <div style=\"display:flex; align-items:center; gap:10px;\">"
                      "    <div style=\"width:8px; height:8px; border-radius:50%; background:#34c759;\"></div>"
                      "    <div>"
                      "      <div style=\"font-weight:600; color:var(--text-color);\">MFA Enabled</div>"
                      "      <div style=\"font-size:0.85rem; color:var(--text-muted);\">Account is secured</div>"
                      "    </div>"
                      "  </div>"
                      "  <a href=\"" +
                          html(navigation.link("/settings/mfa/disable")) +
                          "\" class=\"btn btn-red\" style=\"width:auto; padding:6px 14px; "
                          "font-size:0.85rem;\">Disable</a>"
                          "</div>"
                    : "<div style=\"display:flex; align-items:center; justify-content:space-between; padding:16px; "
                      "background:rgba(255,59,48,0.05); border:1px solid rgba(255,59,48,0.2); border-radius:12px; margin-top:12px;\">"
                      "  <div style=\"display:flex; align-items:center; gap:10px;\">"
                      "    <div style=\"width:8px; height:8px; border-radius:50%; background:#ff3b30;\"></div>"
                      "    <div>"
                      "      <div style=\"font-weight:600; color:var(--text-color);\">MFA Disabled</div>"
                      "      <div style=\"font-size:0.85rem; color:var(--text-muted);\">Action recommended</div>"
                      "    </div>"
                      "  </div>"
                      "  <a href=\"" +
                          html(navigation.link("/auth/enroll/totp")) +
                          "\" class=\"btn\" style=\"width:auto; padding:6px 14px; font-size:0.85rem;\">Enable</a>"
                          "</div>";

            // Optional success/error feedback box (shown after a save/change/delete).
            std::string msgBox;
            if (!message.empty()) {
                const std::string rgb = isError ? "255,59,48" : "52,199,89";
                msgBox = "<div style=\"padding:12px 16px; margin-bottom:16px; border-radius:10px; background:rgba(" + rgb +
                         ",0.1); border:1px solid rgba(" + rgb + ",0.3); color:var(--text-color); font-size:0.9rem;\">" + message +
                         "</div>\n";
            }

            // Password section: only a local account has a password to change.
            // Federated (e.g. Google) accounts sign in through their provider, so no
            // password UI is shown for them.
            std::string passwordSection;
            if (!isFederated) {
                passwordSection =
                    "<div class=\"divider\"></div>\n"
                    "<h3 style=\"font-size:1.1rem; font-weight:600;\">Change Password</h3>\n"
                    "<form method=\"POST\" action=\"" +
                    html(navigation.link("/settings/password")) +
                    "\">\n"
                    "<div class=\"form-group\"><label>Current password</label><input type=\"password\" name=\"current_password\" "
                    "placeholder=\"Current password\" required></div>\n"
                    "<div class=\"form-group\"><label>New password</label><input type=\"password\" name=\"new_password\" placeholder=\"New "
                    "password (min. 8 characters)\" minlength=\"8\" maxlength=\"128\" required></div>\n"
                    "<div class=\"form-group\"><label>Confirm new password</label><input type=\"password\" name=\"confirm_password\" "
                    "placeholder=\"Repeat new password\" minlength=\"8\" maxlength=\"128\" required></div>\n"
                    "<div style=\"display:flex; gap:10px;\"><button type=\"submit\" class=\"btn\" style=\"flex:1;\">Change "
                    "Password</button>" +
                    cancelBtn +
                    "</div>\n"
                    "</form>\n";
            }

            std::string body =
                "<div class=\"card\" style=\"max-width: 520px;\">\n"
                "<svg class=\"logo-icon\"><use href=\"#icon-settings\"/></svg>\n"
                "<h1>Account Settings</h1>\n"
                "<p class=\"subtitle\">Manage your profile and security</p>\n" +
                msgBox +
                // Editable profile (username + email)
                "<form method=\"POST\" action=\"" + html(navigation.link("/settings/profile")) +
                "\">\n"
                "<div class=\"form-group\"><label>Username</label><input type=\"text\" name=\"username\" value=\"" +
                username +
                "\" minlength=\"3\" maxlength=\"64\" required></div>\n"
                "<div class=\"form-group\"><label>Email Address</label><input type=\"email\" name=\"email\" value=\"" +
                email +
                "\" maxlength=\"254\" required></div>\n"
                "<div style=\"display:flex; gap:10px;\"><button type=\"submit\" class=\"btn\" style=\"flex:1;\">Save Profile</button>" +
                cancelBtn +
                "</div>\n"
                "</form>\n" +
                passwordSection +
                // Security (MFA)
                "<div class=\"divider\"></div>\n"
                "<h3 style=\"font-size:1.1rem; font-weight:600;\">Security</h3>\n" +
                mfaStatus +
                // Danger zone (delete account)
                "<div class=\"divider\"></div>\n"
                "<h3 style=\"font-size:1.1rem; font-weight:600; color:#ff3b30;\">Danger Zone</h3>\n"
                "<div style=\"display:flex; align-items:center; justify-content:space-between; padding:16px; "
                "background:rgba(255,59,48,0.05); border:1px solid rgba(255,59,48,0.2); border-radius:12px; margin-top:12px;\">"
                "<div><div style=\"font-weight:600; color:var(--text-color);\">Delete account</div>"
                "<div style=\"font-size:0.85rem; color:var(--text-muted);\">Permanently remove this account, its sessions and "
                "MFA</div></div>"
                "<a href=\"" +
                html(navigation.link("/settings/delete")) +
                "\" class=\"btn btn-red\" style=\"width:auto; padding:6px 14px; font-size:0.85rem;\">Delete</a>"
                "</div>\n" +
                "</div>\n";

            std::string headerName = formatUserDisplayName(username, email);
            return buildPage(navigation, "Settings", body, true, headerName);
        }

        // Detects accounts that have no local password (created via a federated
        // provider such as Google). Such accounts carry a sentinel password hash.
        bool isFederatedAccount(const std::string& passwordHash) {
            return passwordHash.rfind("$federated$", 0) == 0;
        }

        std::string deleteAccountConfirmPage(const Navigation& navigation,
                                             const std::string& raw_username,
                                             const std::string& raw_email,
                                             const std::string& raw_message = "",
                                             bool isError = false,
                                             bool isFederated = false,
                                             bool mfaEnabled = false) {
            const auto username = html(raw_username);
            const auto email = html(raw_email);
            const auto message = html(raw_message);

            std::string msgBox;
            if (!message.empty()) {
                const std::string rgb = isError ? "255,59,48" : "52,199,89";
                msgBox = "<div style=\"padding:12px 16px; margin-bottom:16px; border-radius:10px; background:rgba(" + rgb +
                         ",0.1); border:1px solid rgba(" + rgb + ",0.3); color:var(--text-color); font-size:0.9rem;\">" + message +
                         "</div>\n";
            }
            // Local accounts re-authenticate with their password before this
            // irreversible action. Federated (passwordless) accounts have no local
            // password, so they confirm by typing their username only.
            std::string pwField;
            if (!isFederated) {
                pwField = "<div class=\"form-group\"><label>Enter your password to confirm</label>"
                          "<input type=\"password\" name=\"password\" placeholder=\"Your password\" autocomplete=\"off\" required></div>\n";
            }
            // Accounts with TOTP enabled additionally confirm with a current code,
            // regardless of whether they are local or federated.
            std::string codeField;
            if (mfaEnabled) {
                codeField = "<div class=\"form-group\"><label>Enter your current authenticator code</label>"
                            "<input type=\"text\" name=\"code\" inputmode=\"numeric\" pattern=\"[0-9]*\" maxlength=\"6\" "
                            "placeholder=\"123456\" autocomplete=\"off\" required></div>\n";
            }
            std::string body = "<div class=\"card\" style=\"max-width: 480px;\">\n"
                               "<svg class=\"logo-icon\"><use href=\"#icon-shield\"/></svg>\n"
                               "<h1>Delete Account</h1>\n"
                               "<p class=\"subtitle\">This permanently removes your account, its sessions and any MFA enrolment. This "
                               "cannot be undone.</p>\n" +
                               msgBox + "<form method=\"POST\" action=\"" + html(navigation.link("/settings/delete")) +
                               "\">\n"
                               "<div class=\"form-group\"><label>Type your username <b>" +
                               username +
                               "</b> to confirm</label>"
                               "<input type=\"text\" name=\"confirm_username\" placeholder=\"" +
                               username + "\" autocomplete=\"off\" autocapitalize=\"off\" required></div>\n" + pwField + codeField +
                               "<button type=\"submit\" class=\"btn btn-red\">Delete my account permanently</button>\n"
                               "</form>\n"
                               "<div class=\"links\"><a href=\"" +
                               html(navigation.link("/settings")) +
                               "\">Cancel</a></div>\n"
                               "</div>\n";
            std::string headerName = formatUserDisplayName(username, email);
            return buildPage(navigation, "Delete Account", body, true, headerName);
        }

        std::string mfaDisableConfirmPage(const Navigation& navigation,
                                          const std::string& raw_error,
                                          const std::string& raw_username,
                                          const std::string& raw_email,
                                          bool isFederated = false) {
            const auto error = html(raw_error);
            const auto username = html(raw_username);
            const auto email = html(raw_email);

            std::string err = error.empty() ? "" : "<div class=\"error-box\">" + error + "</div>\n";

            // Local accounts re-authenticate with password + MFA code. Federated
            // (passwordless) accounts have no local password, so the MFA code alone
            // confirms the action.
            std::string pwField;
            if (!isFederated) {
                pwField = "<div class=\"form-group\">\n"
                          "<label>Password</label>\n"
                          "<input type=\"password\" name=\"password\" placeholder=\"Enter your password\" required autofocus>\n"
                          "</div>\n";
            }
            const std::string subtitle = isFederated ? "Enter your MFA code to disable Two-Factor Authentication"
                                                     : "Confirm your password and MFA code to disable Two-Factor Authentication";
            const std::string codeAutofocus = isFederated ? " autofocus" : "";

            std::string body =
                "<div class=\"card\">\n"
                "<svg class=\"logo-icon\" style=\"fill:#ef4444; width:48px; height:48px; margin:0 auto 16px auto; display:block;\"><use "
                "href=\"#icon-shield\"/></svg>\n"
                "<h1 style=\"text-align:center;\">Disable MFA</h1>\n"
                "<p class=\"subtitle\" style=\"text-align:center;\">" +
                subtitle + "</p>\n" + err + "<form method=\"POST\" action=\"" + html(navigation.link("/settings/mfa/disable")) + "\">\n" +
                pwField +
                "<div class=\"form-group\">\n"
                "<label>Verification Code</label>\n"
                "<input type=\"text\" name=\"code\" placeholder=\"000000\" maxlength=\"6\" "
                "pattern=\"[0-9]{6}\" required" +
                codeAutofocus +
                " autocomplete=\"one-time-code\" inputmode=\"numeric\" "
                "style=\"font-size:1.8rem;letter-spacing:10px;text-align:center;\">\n"
                "</div>\n"
                "<button type=\"submit\" class=\"btn btn-red\" style=\"width:100%; margin-top:16px;\">Verify & Disable MFA</button>\n"
                "</form>\n"
                "<div class=\"links\" style=\"text-align:center; margin-top:16px;\">\n"
                "<a href=\"" +
                html(navigation.link("/settings")) +
                "\">Cancel and Return</a>\n"
                "</div>\n"
                "</div>\n";
            std::string headerName = formatUserDisplayName(username, email);
            return buildPage(navigation, "Disable MFA", body, true, headerName);
        }

        std::string forgotPasswordPage(const Navigation& navigation, const std::string& raw_error, const std::string& raw_info) {
            const auto error = html(raw_error);
            const auto info = html(raw_info);

            std::string msg = error.empty() ? (info.empty() ? "" : "<div class=\"info-box\">" + info + "</div>\n")
                                            : "<div class=\"error-box\">" + error + "</div>\n";

            std::string body = "<div class=\"card\">\n"
                               "<div class=\"logo\">🔑</div>\n"
                               "<h1>Forgot Password</h1>\n"
                               "<p class=\"subtitle\">Enter your email to receive a reset link</p>\n" +
                               msg + "<form method=\"POST\" action=\"" + html(navigation.link("/auth/forgot-password")) +
                               "\">\n"
                               "<div class=\"form-group\">\n"
                               "<label>Email Address</label>\n"
                               "<input type=\"email\" name=\"email\" placeholder=\"your@email.com\" required autofocus>\n"
                               "</div>\n"
                               "<button type=\"submit\" class=\"btn\">Send Reset Link</button>\n"
                               "</form>\n"
                               "<div class=\"links\"><a href=\"" +
                               html(navigation.link("/auth/login")) +
                               "\">Back to Sign In</a></div>\n"
                               "</div>\n";
            return buildPage(navigation, "Forgot Password", body);
        }

        std::string resetPasswordPage(const Navigation& navigation, const std::string& raw_token, const std::string& raw_error) {
            const auto token = html(raw_token);
            const auto error = html(raw_error);

            std::string err = error.empty() ? "" : "<div class=\"error-box\">" + error + "</div>\n";

            std::string body = "<div class=\"card\">\n"
                               "<div class=\"logo\">🔐</div>\n"
                               "<h1>Reset Password</h1>\n"
                               "<p class=\"subtitle\">Choose a new password for your account</p>\n" +
                               err + "<form method=\"POST\" action=\"" + html(navigation.link("/auth/reset-password")) +
                               "\">\n"
                               "<input type=\"hidden\" name=\"token\" value=\"" +
                               token +
                               "\">\n"
                               "<div class=\"form-group\">\n"
                               "<label>New Password</label>\n"
                               "<input type=\"password\" name=\"password\" placeholder=\"New password\" required autofocus>\n"
                               "</div>\n"
                               "<div class=\"form-group\">\n"
                               "<label>Confirm Password</label>\n"
                               "<input type=\"password\" name=\"password_confirm\" placeholder=\"Confirm new password\" required>\n"
                               "</div>\n"
                               "<button type=\"submit\" class=\"btn btn-green\">Reset Password</button>\n"
                               "</form>\n"
                               "</div>\n";
            return buildPage(navigation, "Reset Password", body);
        }

        std::string successPage(const Navigation& navigation,
                                const std::string& raw_heading,
                                const std::string& raw_message,
                                const std::string& raw_linkUrl,
                                const std::string& raw_linkText) {
            const auto heading = html(raw_heading);
            const auto message = html(raw_message);
            const auto linkUrl = html(navigation.link(raw_linkUrl));
            const auto linkText = html(raw_linkText);

            std::string body = "<div class=\"card\">\n"
                               "<div class=\"logo\">✅</div>\n"
                               "<h1>" +
                               heading +
                               "</h1>\n"
                               "<p class=\"subtitle\">" +
                               message +
                               "</p>\n"
                               "<div class=\"divider\"></div>\n"
                               "<a href=\"" +
                               linkUrl + "\" class=\"btn btn-green\">" + linkText +
                               "</a>\n"
                               "</div>\n";
            return buildPage(navigation, raw_heading, body);
        }

        std::string errorPage(const Navigation& navigation, const std::string& raw_message) {
            const auto message = html(raw_message);

            std::string body = "<div class=\"card\">\n"
                               "<div class=\"logo\">⚠️</div>\n"
                               "<h1>Error</h1>\n"
                               "<div class=\"error-box\">" +
                               message +
                               "</div>\n"
                               "<a href=\"" +
                               html(navigation.link("/auth/login")) +
                               "\" class=\"btn btn-secondary\">Back to Login</a>\n"
                               "</div>\n";
            return buildPage(navigation, "Error", body);
        }

        std::map<std::string, std::string> cookieOptions(unsigned seconds) {
            std::map<std::string, std::string> options{
                {"HttpOnly", ""}, {"SameSite", "Lax"}, {"Path", "/"}, {"Max-Age", std::to_string(seconds)}};
            if (config.issuer.starts_with("https://")) {
                options["Secure"] = "";
            }
            return options;
        }
        void startFlow(const auto& req, const auto& res, const Json& context) {
            if (!req->cookie("auth_flow").empty()) {
                store.execute("DELETE FROM auth_flow WHERE token_hash=?", {sha256(req->cookie("auth_flow"))});
            }
            const auto token = store.begin(context);
            req->cookies["auth_flow"] = token;
            res->cookie("auth_flow", token, cookieOptions(600));
        }
        void finishLogin(
            const Navigation& navigation, const auto& req, const auto& res, const std::string& userId, bool mfa, bool enrollment = false) {
            auto context = store.flow(req->cookie("auth_flow"));
            if (!mfa && context.value("acr_values", std::string()) == "urn:snodec:acr:mfa") {
                bool enabled = false;
                require(db.query("SELECT totp_enabled FROM user WHERE id=?",
                                 {userId},
                                 [&](const auto& row) {
                                     enabled = row.get(0) == "1";
                                 }),
                        "MFA lookup failed");
                context["enrollment"] = !enabled;
                store.save(req->cookie("auth_flow"), context);
                if (enabled) {
                    res->send(mfaPage(navigation, sha256(req->cookie("auth_flow"))));
                } else {
                    res->redirect(navigation.link("/auth/enroll/totp"));
                }
            } else {
                const auto result = store.complete(req->cookie("auth_flow"), userId, mfa, enrollment);
                if (!result.at("session_cookie").template get<std::string>().empty()) {
                    res->cookie("snodec_session", result.at("session_cookie"), cookieOptions(86400));
                }
                res->cookie("auth_flow", "", cookieOptions(0));
                if (result.value("client_id", std::string()).empty()) {
                    res->redirect(navigation.link(navigation.target.empty() ? "/dashboard" : "/settings"));
                } else {
                    const std::string target = result.at("redirect_uri");
                    res->redirect(target + (target.find('?') == std::string::npos ? "?" : "&") +
                                  formEncode({{"code", result.at("code")}, {"state", result.at("state")}}));
                }
            }
        }
        std::string requireSession(const auto& req, const auto&) {
            const auto session = store.session(req->cookie("snodec_session"));
            return session.is_object() ? session.at("user_id").template get<std::string>() : "";
        }
        auto safe(auto handler) {
            return [handler, owner = shared_from_this()] MIDDLEWARE(req, res, next) {
                res->set("Cache-Control", "no-store")
                    .set("Referrer-Policy", "strict-origin")
                    .set("X-Content-Type-Options", "nosniff")
                    .set("Content-Security-Policy", "frame-ancestors 'none'; base-uri 'none'");
                const bool backchannel = req->url == "/oauth2/token" || req->url == "/oauth2/introspect";
                const bool mutation = req->method != "GET" && req->method != "HEAD" && req->method != "OPTIONS";
                if ((backchannel && !req->cookies.empty()) || (mutation && !backchannel && req->get("Origin") != owner->config.issuer)) {
                    res->status(403).send("Untrusted request origin");
                } else {
                    try {
                        Navigation navigation{req->query("client_id"), req->query("return")};
                        if (!navigation.target.empty()) {
                            owner->store.accountReturn(navigation.clientId, navigation.target);
                        }
                        const bool usesFlow = req->path == "/auth/login" || req->path == "/auth/register" || req->path == "/auth/mfa" ||
                                              req->path.starts_with("/auth/enroll/totp") || req->path.starts_with("/auth/federated/google");
                        Json pending = Json::object();
                        if (usesFlow && req->method == "POST") {
                            pending = owner->store.formFlow(req->cookie("auth_flow"), owner->parseBody(req->body)["transaction"]);
                        } else if (usesFlow && !navigation.target.empty()) {
                            try {
                                pending = owner->store.flow(req->cookie("auth_flow"));
                            } catch (const std::exception&) {
                            }
                        }
                        if (!navigation.target.empty() && !pending.value("client_id", std::string()).empty()) {
                            res->status(409).send(owner->buildPage(
                                navigation,
                                "Sign-in already in progress",
                                "<div class=\"card\"><h1>Sign-in already in progress</h1>"
                                "<p>Finish the application sign-in in its original tab, then retry account settings.</p></div>"));
                        } else {
                            handler(navigation, req, res);
                        }
                    } catch (const std::exception&) {
                        if (req->path == "/oauth2/token") {
                            res->status(400).set("Content-Type", "application/json").send(R"({"error":"invalid_grant"})");
                        } else if (req->path == "/oauth2/userinfo") {
                            res->status(401)
                                .set("WWW-Authenticate", "Bearer error=\"invalid_token\"")
                                .set("Content-Type", "application/json")
                                .send(R"({"error":"invalid_token"})");
                        } else {
                            res->status(400).send("Request rejected; restart the operation");
                        }
                    }
                }
            };
        }

        JwtClaims verifiedToken(const std::string& token, const std::string& clientId) {
            JwtClaims claims;
            std::string error;
            JwtVerifier verifier(config.issuer, clientId, jwtSigner.publicKey());
            require(verifier.verify(token, claims, error) && store.active(claims.sessionId, claims.subject, claims.mfaVerified),
                    "Inactive token");
            return claims;
        }

        void mount(const express::Router& app) {
            // ── GET / ─────────────────────────────────────────────────────────────────
            app.get("/", safe([this](const Navigation& navigation, const auto& req, const auto& res) {
                        if (!requireSession(req, res).empty()) {
                            res->redirect(navigation.link("/dashboard"));
                        } else {
                            res->send(landingPage(navigation));
                        }
                    }));

            // ── GET /dashboard ────────────────────────────────────────────────────────
            app.get(
                "/dashboard", safe([this](const Navigation& navigation, const auto& req, const auto& res) {
                    std::string userId = requireSession(req, res);
                    if (userId.empty()) {
                        res->redirect(navigation.link("/auth/login"));
                    } else {
                        std::string username, email;
                        int mfaEnabled = 0;
                        db.query("SELECT username, email, totp_enabled FROM user WHERE id=?", {userId}, [&](const SqliteDatabase::Row& r) {
                            username = r.get(0);
                            email = r.get(1);
                            mfaEnabled = std::stoi(r.get(2));
                        });

                        int totalUsers = 0, activeSessions = 0, pendingTokens = 0, mfaUsers = 0;
                        db.query("SELECT COUNT(*) FROM user", {}, [&](const SqliteDatabase::Row& r) {
                            totalUsers = std::stoi(r.get(0));
                        });
                        db.query(
                            "SELECT COUNT(*) FROM session WHERE expires_at > CURRENT_TIMESTAMP", {}, [&](const SqliteDatabase::Row& r) {
                                activeSessions = std::stoi(r.get(0));
                            });
                        db.query("SELECT COUNT(*) FROM auth_code", {}, [&](const SqliteDatabase::Row& r) {
                            pendingTokens = std::stoi(r.get(0));
                        });
                        db.query("SELECT COUNT(*) FROM user WHERE totp_enabled=1", {}, [&](const SqliteDatabase::Row& r) {
                            mfaUsers = std::stoi(r.get(0));
                        });

                        std::string headerName = formatUserDisplayName(username, email);
                        res->send(dashboardPage(
                            navigation, headerName, totalUsers, activeSessions, pendingTokens, mfaUsers, formatUptime(), mfaEnabled > 0));
                    }
                }));

            // ── GET /settings ─────────────────────────────────────────────────────────
            app.get("/settings", safe([this](const Navigation& navigation, const auto& req, const auto& res) {
                        std::string userId = requireSession(req, res);
                        if (userId.empty()) {
                            res->redirect(navigation.link("/auth/login"));
                        } else {
                            std::string username, email, passwordHash;
                            int mfaEnabled = 0;
                            db.query("SELECT username, email, totp_enabled, password_hash FROM user WHERE id=?",
                                     {userId},
                                     [&](const SqliteDatabase::Row& r) {
                                         username = r.get(0);
                                         email = r.get(1);
                                         mfaEnabled = std::stoi(r.get(2));
                                         passwordHash = r.get(3);
                                     });

                            // Optional feedback after a profile/password update (?msg=...&err=1),
                            // and an optional "back to app" target carried by the Account button.
                            const std::string msg = urlDecode(req->query("msg"));
                            const bool isErr = req->query("err") == "1";
                            res->send(
                                settingsPage(navigation, username, email, mfaEnabled > 0, isFederatedAccount(passwordHash), msg, isErr));
                        }
                    }));

            // ── GET /settings/mfa/disable ─────────────────────────────────────────────
            app.get("/settings/mfa/disable", safe([this](const Navigation& navigation, const auto& req, const auto& res) {
                        std::string userId = requireSession(req, res);
                        if (userId.empty()) {
                            res->redirect(navigation.link("/auth/login"));
                        } else {
                            std::string username, email, hash;
                            int mfaEnabled = 0;
                            db.query("SELECT username, email, totp_enabled, password_hash FROM user WHERE id=?",
                                     {userId},
                                     [&](const SqliteDatabase::Row& r) {
                                         username = r.get(0);
                                         email = r.get(1);
                                         mfaEnabled = std::stoi(r.get(2));
                                         hash = r.get(3);
                                     });

                            if (mfaEnabled <= 0) {
                                res->redirect(navigation.link("/settings"));
                            } else {
                                res->send(mfaDisableConfirmPage(navigation, "", username, email, isFederatedAccount(hash)));
                            }
                        }
                    }));

            // ── POST /settings/mfa/disable ────────────────────────────────────────────
            app.post(
                "/settings/mfa/disable", safe([this](const Navigation& navigation, const auto& req, const auto& res) {
                    std::string userId = requireSession(req, res);
                    if (userId.empty()) {
                        res->redirect(navigation.link("/auth/login"));
                    } else {
                        auto p = parseBody(req->body);
                        const std::string password = p["password"];
                        const std::string code = p["code"];

                        std::string username, email, hash, salt, totpSecret;
                        int mfaEnabled = 0;
                        db.query("SELECT username, email, password_hash, password_salt, totp_enabled, totp_secret FROM user WHERE id=?",
                                 {userId},
                                 [&](const SqliteDatabase::Row& r) {
                                     username = r.get(0);
                                     email = r.get(1);
                                     hash = r.get(2);
                                     salt = r.get(3);
                                     mfaEnabled = std::stoi(r.get(4));
                                     totpSecret = r.get(5);
                                 });

                        if (mfaEnabled <= 0) {
                            res->redirect(navigation.link("/settings"));
                        } else {
                            // Local accounts must re-authenticate with their password; federated
                            // (passwordless) accounts have none, so the MFA code alone gates this.
                            const bool federated = isFederatedAccount(hash);
                            bool needsMigration = false;
                            if (!federated && !verifyPasswordAny(password, hash, salt, needsMigration)) {
                                res->status(400).send(
                                    mfaDisableConfirmPage(navigation, "Invalid password. Please try again.", username, email, federated));
                            } else {
                                if (needsMigration) {
                                    migratePasswordHash(userId, password);
                                }

                                std::string decryptedSecret = decryptTotpSecret(totpSecret);
                                if (!Totp::verifyCode(decryptedSecret, code)) {
                                    res->status(400).send(mfaDisableConfirmPage(
                                        navigation, "Invalid verification code. Please try again.", username, email, federated));
                                } else {
                                    std::string err;
                                    if (!db.exec("UPDATE user SET totp_enabled=0, totp_secret=NULL WHERE id=?", {userId}, &err)) {
                                        res->status(500).send(errorPage(navigation, "DB error: " + err));
                                    } else {
                                        res->redirect(navigation.link("/settings"));
                                    }
                                }
                            }
                        }
                    }
                }));

            // ── POST /settings/profile (update username + email) ──────────────────────
            app.post(
                "/settings/profile", safe([this](const Navigation& navigation, const auto& req, const auto& res) {
                    std::string userId = requireSession(req, res);
                    if (userId.empty()) {
                        res->redirect(navigation.link("/auth/login"));
                    } else {
                        auto p = parseBody(req->body);
                        const std::string newUsername = p["username"], newEmail = p["email"];
                        if (newUsername.size() < 3 || newUsername.size() > 64 || newEmail.empty() || newEmail.size() > 254 ||
                            newEmail.find('@') == std::string::npos) {
                            res->redirect(navigation.link(
                                "/settings?err=1&msg=" + snodec::auth::urlEncode("Please enter a valid username (3-64 chars) and email.")));
                        } else {
                            bool taken = false;
                            db.query("SELECT id FROM user WHERE (username=? OR email=?) AND id<>?",
                                     {newUsername, newEmail, userId},
                                     [&](const SqliteDatabase::Row&) {
                                         taken = true;
                                     });
                            if (taken) {
                                res->redirect(navigation.link("/settings?err=1&msg=" +
                                                              snodec::auth::urlEncode("That username or email is already in use.")));
                            } else {
                                std::string err;
                                if (!db.exec("UPDATE user SET username=?, email=? WHERE id=?", {newUsername, newEmail, userId}, &err)) {
                                    res->redirect(navigation.link("/settings?err=1&msg=" +
                                                                  snodec::auth::urlEncode("Could not save profile: " + err)));
                                } else {
                                    res->redirect(
                                        navigation.link("/settings?msg=" +
                                                        snodec::auth::urlEncode(
                                                            "Profile updated. Sign in again at applications to refresh profile claims.")));
                                }
                            }
                        }
                    }
                }));

            // ── POST /settings/password (change for local / set for federated) ────────
            app.post(
                "/settings/password", safe([this](const Navigation& navigation, const auto& req, const auto& res) {
                    std::string userId = requireSession(req, res);
                    if (userId.empty()) {
                        res->redirect(navigation.link("/auth/login"));
                    } else {
                        auto p = parseBody(req->body);
                        const std::string currentPw = p["current_password"], newPw = p["new_password"], confirmPw = p["confirm_password"];
                        if (newPw.size() < 8 || newPw.size() > 128) {
                            res->redirect(navigation.link("/settings?err=1&msg=" +
                                                          snodec::auth::urlEncode("New password must be 8-128 characters.")));
                        } else {
                            if (newPw != confirmPw) {
                                res->redirect(
                                    navigation.link("/settings?err=1&msg=" + snodec::auth::urlEncode("New passwords do not match.")));
                            } else {
                                std::string hash, salt;
                                db.query("SELECT password_hash, password_salt FROM user WHERE id=?",
                                         {userId},
                                         [&](const SqliteDatabase::Row& r) {
                                             hash = r.get(0);
                                             salt = r.get(1);
                                         });
                                const bool federated = isFederatedAccount(hash);
                                bool needsMigration = false;
                                if (!federated && !verifyPasswordAny(currentPw, hash, salt, needsMigration)) {
                                    res->redirect(navigation.link("/settings?err=1&msg=" +
                                                                  snodec::auth::urlEncode("Your current password is incorrect.")));
                                } else {
                                    // The current password is correct here, so an identical new password
                                    // is just a reuse of the old one — reject it.
                                    if (!federated && newPw == currentPw) {
                                        res->redirect(navigation.link(
                                            "/settings?err=1&msg=" +
                                            snodec::auth::urlEncode("New password must be different from your current password.")));
                                    } else {
                                        std::string err;
                                        if (!db.exec("UPDATE user SET password_hash=?, password_salt='' WHERE id=?",
                                                     {PasswordHasher::hashPassword(newPw), userId},
                                                     &err)) {
                                            res->redirect(navigation.link("/settings?err=1&msg=" +
                                                                          snodec::auth::urlEncode("Could not update password: " + err)));
                                        } else {
                                            res->redirect(navigation.link(
                                                "/settings?msg=" +
                                                snodec::auth::urlEncode(
                                                    federated ? "Password set. You can now also sign in with username and password."
                                                              : "Password changed.")));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }));

            // ── GET /settings/delete (confirmation page) ──────────────────────────────
            app.get("/settings/delete", safe([this](const Navigation& navigation, const auto& req, const auto& res) {
                        std::string userId = requireSession(req, res);
                        if (userId.empty()) {
                            res->redirect(navigation.link("/auth/login"));
                        } else {
                            std::string username, email, hash;
                            int mfaEnabled = 0;
                            db.query("SELECT username, email, password_hash, totp_enabled FROM user WHERE id=?",
                                     {userId},
                                     [&](const SqliteDatabase::Row& r) {
                                         username = r.get(0);
                                         email = r.get(1);
                                         hash = r.get(2);
                                         mfaEnabled = std::stoi(r.get(3));
                                     });
                            res->send(
                                deleteAccountConfirmPage(navigation, username, email, "", false, isFederatedAccount(hash), mfaEnabled > 0));
                        }
                    }));

            // ── POST /settings/delete (permanently remove the account) ────────────────
            app.post(
                "/settings/delete", safe([this](const Navigation& navigation, const auto& req, const auto& res) {
                    std::string userId = requireSession(req, res);
                    if (userId.empty()) {
                        res->redirect(navigation.link("/auth/login"));
                    } else {
                        std::string username, email, hash, salt, totpSecret;
                        int mfaEnabled = 0;
                        db.query("SELECT username, email, password_hash, password_salt, totp_enabled, totp_secret FROM user WHERE id=?",
                                 {userId},
                                 [&](const SqliteDatabase::Row& r) {
                                     username = r.get(0);
                                     email = r.get(1);
                                     hash = r.get(2);
                                     salt = r.get(3);
                                     mfaEnabled = std::stoi(r.get(4));
                                     totpSecret = r.get(5);
                                 });
                        const bool federated = isFederatedAccount(hash);
                        const bool mfa = mfaEnabled > 0;
                        auto p = parseBody(req->body);
                        if (p["confirm_username"] != username) {
                            res->status(400).send(deleteAccountConfirmPage(navigation,
                                                                           username,
                                                                           email,
                                                                           "The username did not match. Your account was not deleted.",
                                                                           true,
                                                                           federated,
                                                                           mfa));
                        } else {
                            // Local accounts must re-authenticate with their password before this
                            // irreversible action. Federated (passwordless) accounts confirm by
                            // username only — they have no local password to enter.
                            bool needsMigration = false;
                            if (!federated && !verifyPasswordAny(p["password"], hash, salt, needsMigration)) {
                                res->status(400).send(deleteAccountConfirmPage(navigation,
                                                                               username,
                                                                               email,
                                                                               "Your password was incorrect. Your account was not deleted.",
                                                                               true,
                                                                               federated,
                                                                               mfa));
                            } else {
                                // Accounts with MFA enabled must also confirm with a current TOTP code,
                                // whether the account is local or federated.
                                if (mfa && !Totp::verifyCode(decryptTotpSecret(totpSecret), p["code"])) {
                                    res->status(400).send(
                                        deleteAccountConfirmPage(navigation,
                                                                 username,
                                                                 email,
                                                                 "Your authenticator code was incorrect. Your account was not deleted.",
                                                                 true,
                                                                 federated,
                                                                 mfa));
                                } else {
                                    std::string err;

                                    if (!db.exec("DELETE FROM user WHERE id=?", {userId}, &err)) {
                                        res->status(500).send(errorPage(navigation, "Could not delete account: " + err));
                                    } else {
                                        res->cookie("snodec_session", "", {{"Path", "/"}, {"Max-Age", "0"}});
                                        res->redirect(navigation.link("/auth/login"));
                                    }
                                }
                            }
                        }
                    }
                }));

            // ── POST /auth/logout ─────────────────────────────────────────────────────
            app.post("/auth/logout", safe([this](const Navigation& navigation, const auto& req, const auto& res) {
                         store.execute("DELETE FROM session WHERE token=?", {sha256(req->cookie("snodec_session"))});
                         res->cookie("snodec_session", "", {{"Path", "/"}, {"Max-Age", "0"}});
                         res->redirect(navigation.link("/auth/login"));
                     }));

            app.get("/auth/logout", safe([this](const Navigation& navigation, const auto&, const auto& res) {
                        res->send(buildPage(navigation,
                                            "Sign out",
                                            "<form method=\"post\" action=\"" + html(navigation.link("/auth/logout")) +
                                                "\"><button>Sign out</button></form>"));
                    }));

            app.get("/auth/login", safe([this](const Navigation& navigation, const auto& req, const auto& res) {
                        Json context;
                        try {
                            context = store.flow(req->cookie("auth_flow"));
                        } catch (const std::exception&) {
                            context = Json::object();
                            startFlow(req, res, context);
                        }
                        const auto session = store.session(req->cookie("snodec_session"));
                        if (session.is_object()) {
                            context["user_id"] = session.at("user_id");
                            context["sid"] = session.at("sid");
                            context["mfa_verified"] = session.at("mfa_verified");
                            store.save(req->cookie("auth_flow"), context);
                            finishLogin(navigation, req, res, context.at("user_id"), session.at("mfa_verified"));
                        } else {
                            res->send(loginPage(navigation, sha256(req->cookie("auth_flow"))));
                        }
                    }));
            app.get("/auth/register", safe([this](const Navigation& navigation, const auto& req, const auto& res) {
                        try {
                            store.flow(req->cookie("auth_flow"));
                        } catch (const std::exception&) {
                            startFlow(req, res, Json::object());
                        }
                        res->send(registerPage(navigation, sha256(req->cookie("auth_flow"))));
                    }));
            app.post("/auth/register", safe([this](const Navigation& navigation, const auto& req, const auto& res) {
                         auto context = store.flow(req->cookie("auth_flow"));
                         const auto fields = Json(parseBody(req->body));
                         const auto username = fields.value("username", std::string());
                         const auto email = fields.value("email", std::string());
                         const auto password = fields.value("password", std::string());
                         require(username.size() >= 3 && username.size() <= 64 && email.size() <= 254 &&
                                     email.find('@') != std::string::npos && email.find_first_of("\r\n") == std::string::npos &&
                                     password.size() >= 8 && password.size() <= 128 &&
                                     fields.value("confirm_password", std::string()) == password,
                                 "Invalid registration");
                         const bool enroll = fields.value("enable_mfa", std::string()) == "1";
                         store.execute("INSERT INTO user(username,email,password_hash,password_salt,activated) VALUES(?,?,?,'',?)",
                                       {username, email, PasswordHasher::hashPassword(password), enroll ? "0" : "1"});
                         const auto id = std::to_string(db.lastInsertRowid());
                         context["user_id"] = id;
                         context["enrollment"] = enroll;
                         store.save(req->cookie("auth_flow"), context);
                         if (enroll) {
                             res->redirect(navigation.link("/auth/enroll/totp"));
                         } else {
                             finishLogin(navigation, req, res, id, false);
                         }
                     }));
            app.post("/auth/login", safe([this](const Navigation& navigation, const auto& req, const auto& res) {
                         auto context = store.flow(req->cookie("auth_flow"));
                         auto fields = parseBody(req->body);
                         const auto username = fields["username"];
                         require(loginLimiter.isAllowed(username) && fields["password"].size() <= 128, "Login rate limited");
                         std::string id, hash, salt;
                         bool mfa = false, migrate = false;
                         require(db.query("SELECT id,password_hash,password_salt,totp_enabled,activated FROM user WHERE username=?",
                                          {username},
                                          [&](const auto& row) {
                                              id = row.get(0);
                                              hash = row.get(1);
                                              salt = row.get(2);
                                              mfa = row.get(3) == "1";
                                              context["enrollment"] = row.get(4) != "1";
                                          }),
                                 "Login unavailable");
                         if (id.empty() || !verifyPasswordAny(fields["password"], hash, salt, migrate)) {
                             loginLimiter.recordFailure(username);
                             res->status(401).send(loginPage(navigation, sha256(req->cookie("auth_flow")), "Invalid credentials"));
                         } else {
                             if (migrate) {
                                 migratePasswordHash(id, fields["password"]);
                             }
                             loginLimiter.recordSuccess(username);
                             context["user_id"] = id;
                             store.save(req->cookie("auth_flow"), context);
                             if (mfa) {
                                 res->send(mfaPage(navigation, sha256(req->cookie("auth_flow"))));
                             } else if (context.value("enrollment", false)) {
                                 res->redirect(navigation.link("/auth/enroll/totp"));
                             } else {
                                 finishLogin(navigation, req, res, id, false);
                             }
                         }
                     }));
            app.post("/auth/mfa", safe([this](const Navigation& navigation, const auto& req, const auto& res) {
                         const auto context = store.flow(req->cookie("auth_flow"));
                         const auto id = context.at("user_id").template get<std::string>();
                         require(mfaLimiter.isAllowed(id), "MFA rate limited");
                         std::string secret;
                         require(db.query("SELECT totp_secret FROM user WHERE id=? AND totp_enabled=1",
                                          {id},
                                          [&](const auto& row) {
                                              secret = row.get(0);
                                          }),
                                 "MFA unavailable");
                         const auto code = parseBody(req->body)["code"];
                         if (secret.empty() || !Totp::verifyCode(decryptTotpSecret(secret), code)) {
                             mfaLimiter.recordFailure(id);
                             res->status(401).send(mfaPage(navigation, sha256(req->cookie("auth_flow")), "Invalid code"));
                         } else {
                             mfaLimiter.recordSuccess(id);
                             finishLogin(navigation, req, res, id, true);
                         }
                     }));
            app.get("/auth/enroll/totp", safe([this](const Navigation& navigation, const auto& req, const auto& res) {
                        Json context;
                        try {
                            context = store.flow(req->cookie("auth_flow"));
                        } catch (const std::exception&) {
                            context = Json::object();
                        }
                        const auto session = store.session(req->cookie("snodec_session"));
                        if (session.is_object() && !context.value("enrollment", false)) {
                            context.update(session);
                            context["enrollment"] = true;
                            startFlow(req, res, context);
                        }
                        require(context.value("enrollment", false), "Enrollment not authorized");
                        const auto id = context.at("user_id").template get<std::string>();
                        std::string username;
                        require(db.query("SELECT username FROM user WHERE id=? AND totp_enabled=0",
                                         {id},
                                         [&](const auto& row) {
                                             username = row.get(0);
                                         }),
                                "Enrollment unavailable");
                        require(!username.empty(), "Already enrolled or unknown account");
                        const auto secret = Totp::generateSecret();
                        context["secret"] = encryptTotpSecret(secret);
                        store.save(req->cookie("auth_flow"), context);
                        res->send(enrollTotpPage(navigation,
                                                 secret,
                                                 QrCodeGenerator::makeTotpOtpAuthUri("SNode.C", username, secret),
                                                 sha256(req->cookie("auth_flow")),
                                                 context.value("acr_values", std::string()) == "urn:snodec:acr:mfa"));
                    }));
            app.post("/auth/enroll/totp/verify", safe([this](const Navigation& navigation, const auto& req, const auto& res) {
                         auto context = store.flow(req->cookie("auth_flow"));
                         require(context.value("enrollment", false), "Enrollment not authorized");
                         const auto id = context.at("user_id").template get<std::string>();
                         require(mfaLimiter.isAllowed(id), "MFA rate limited");
                         const auto secret = decryptTotpSecret(context.at("secret"));
                         if (!Totp::verifyCode(secret, parseBody(req->body)["code"])) {
                             mfaLimiter.recordFailure(id);
                             res->status(401).send("Invalid code; return to enrollment");
                         } else {
                             finishLogin(navigation, req, res, id, true, true);
                         }
                     }));
            app.post("/auth/enroll/totp/skip", safe([this](const Navigation& navigation, const auto& req, const auto& res) {
                         const auto context = store.flow(req->cookie("auth_flow"));
                         require(context.value("enrollment", false), "Enrollment not authorized");
                         require(context.value("acr_values", std::string()) != "urn:snodec:acr:mfa", "MFA required by application");
                         const auto id = context.at("user_id").template get<std::string>();
                         store.execute("UPDATE user SET activated=1 WHERE id=? AND totp_enabled=0", {id});
                         require(db.changedRows() == 1, "Cannot skip completed MFA");
                         finishLogin(navigation, req, res, id, false);
                     }));

            // ── GET /api/qrcode ───────────────────────────────────────────────────────
            app.get("/api/qrcode", safe([this](const Navigation&, const auto& req, const auto& res) {
                        std::string data = httputils::url_decode(req->query("data"));
                        if (data.empty()) {
                            res->status(400).send("Missing data");
                        } else {
                            try {
                                auto png = QrCodeGenerator::generatePng(data, 4, 4);
                                res->set("Content-Type", "image/png")
                                    .set("Cache-Control", "public,max-age=3600")
                                    .send(reinterpret_cast<const char*>(png.data()), static_cast<std::streamsize>(png.size()));
                            } catch (const std::exception& e) {
                                snode::log::application().error() << "QR generation failed: " << e.what();
                                res->status(500).send("QR generation failed");
                            }
                        }
                    }));

            // ── GET /auth/forgot-password ─────────────────────────────────────────────
            app.get("/auth/forgot-password", safe([this](const Navigation& navigation, const auto&, const auto& res) {
                        res->send(forgotPasswordPage(navigation, "", ""));
                    }));

            app.post("/auth/forgot-password", safe([this](const Navigation& navigation, const auto& req, const auto& res) {
                         const auto email = parseBody(req->body)["email"];
                         require(loginLimiter.isAllowed("reset:" + email), "Reset rate limited");
                         loginLimiter.recordFailure("reset:" + email);
                         store.requestReset(email, [this](const std::string& address, const std::string& token) {
                             sendPasswordResetLink(address, config.issuer + "/auth/reset-password?token=" + urlEncode(token));
                         });
                         res->send(forgotPasswordPage(
                             navigation, "", "If this account exists and delivery is available, a reset email will be sent."));
                     }));

            // ── GET /auth/reset-password ──────────────────────────────────────────────
            app.get("/auth/reset-password", safe([this](const Navigation& navigation, const auto& req, const auto& res) {
                        const std::string token = req->query("token");
                        if (token.empty()) {
                            res->send(errorPage(navigation, "Missing reset token."));
                        } else {
                            // Validate token
                            bool valid = false;
                            db.query("SELECT id FROM password_reset_tokens"
                                     " WHERE token=? AND used=0 AND expires_at > datetime('now')",
                                     {sha256(token)},
                                     [&](const SqliteDatabase::Row&) {
                                         valid = true;
                                     });
                            if (!valid) {
                                res->send(errorPage(navigation,
                                                    "This reset link is invalid or has expired."
                                                    " Please request a new one."));
                            } else {
                                res->send(resetPasswordPage(navigation, token, ""));
                            }
                        }
                    }));

            // ── POST /auth/reset-password ─────────────────────────────────────────────
            app.post(
                "/auth/reset-password", safe([this](const Navigation& navigation, const auto& req, const auto& res) {
                    auto p = parseBody(req->body);
                    const std::string token = p["token"], pw = p["password"], pw2 = p["password_confirm"];
                    if (token.empty() || pw.size() < 8 || pw.size() > 128) {
                        res->send(resetPasswordPage(navigation, token, "All fields are required."));
                    } else {
                        if (pw != pw2) {
                            res->send(resetPasswordPage(navigation, token, "Passwords do not match."));
                        } else {
                            store.resetPassword(token, PasswordHasher::hashPassword(pw));
                            res->send(successPage(
                                navigation, "Password Reset", "Your password has been updated successfully.", "/auth/login", "Sign In"));
                        }
                    }
                }));

            // ── GET /auth/help/authenticator ──────────────────────────────────────────
            app.get("/auth/help/authenticator", safe([this](const Navigation& navigation, const auto&, const auto& res) {
                        std::string body = "<div class=\"card\" style=\"max-width:600px;\">\n"
                                           "<a href=\"javascript:history.back()\" style=\"color:#63b3ed;"
                                           "font-size:0.85rem;text-decoration:none;\">← Back</a>\n"
                                           "<div class=\"logo\" style=\"margin-top:16px;\">📱</div>\n"
                                           "<h1>Authenticator App Setup</h1>\n"
                                           "<p class=\"subtitle\">Step-by-step guide</p>\n"
                                           "<div class=\"info-box\" style=\"margin:20px 0;text-align:left;\">\n"
                                           "<strong>Supported Apps:</strong><br>\n"
                                           "🟢 Google Authenticator &nbsp;|&nbsp; "
                                           "🔵 Microsoft Authenticator &nbsp;|&nbsp; "
                                           "⚫ Authy\n</div>\n"
                                           "<ol style=\"padding-left:20px;color:#ccc;line-height:2.2;\">\n"
                                           "<li>Install your authenticator app from the App Store or Play Store</li>\n"
                                           "<li>Tap <strong>+</strong> or <em>Add Account</em></li>\n"
                                           "<li>Select <strong>Scan QR Code</strong></li>\n"
                                           "<li>Point your camera at the QR code on the setup page</li>\n"
                                           "<li>Enter the 6-digit code shown in the app to confirm setup</li>\n"
                                           "</ol>\n"
                                           "<div class=\"info-box\" style=\"margin-top:20px;\">\n"
                                           "💡 <strong>Can't scan?</strong> Use the manual entry key shown "
                                           "below the QR code — tap <em>Enter setup key</em> in your app.\n"
                                           "</div>\n</div>\n";
                        res->send(buildPage(navigation, "Authenticator Help", body));
                    }));

            app.get("/oauth2/authorize", safe([this](const Navigation& navigation, const auto& req, const auto& res) {
                        startFlow(req, res, store.authorization(Json(req->queries)));
                        res->redirect(navigation.link("/auth/login"));
                    }));
            app.post("/oauth2/token", safe([this](const Navigation&, const auto& req, const auto& res) {
                         const auto context = store.redeem(Json(parseBody(req->body)));
                         JwtClaims claims;
                         claims.subject = context.at("user_id");
                         claims.sessionId = context.at("sid");
                         claims.audience = context.at("client_id");
                         claims.mfaVerified = context.at("mfa_verified");
                         claims.nonce = context.value("nonce", std::string());
                         claims.expiresAt = std::chrono::system_clock::now() + std::chrono::seconds(300);
                         require(db.query("SELECT username,email FROM user WHERE id=?",
                                          {claims.subject},
                                          [&](const auto& row) {
                                              claims.username = row.get(0);
                                              claims.email = row.get(1);
                                          }),
                                 "User lookup failed");
                         std::istringstream scopes(context.value("scope", std::string()));
                         std::string scope;
                         while (scopes >> scope) {
                             require(scope == "openid" || scope == "profile" || scope == "email", "Unsupported scope");
                             claims.scopes.push_back(scope);
                         }
                         Json result = {{"access_token", jwtSigner.sign(claims)},
                                        {"token_type", "Bearer"},
                                        {"expires_in", 300},
                                        {"refresh_token", context.at("refresh_token")}};
                         if (std::find(claims.scopes.begin(), claims.scopes.end(), "openid") != claims.scopes.end()) {
                             claims.purpose = "id";
                             result["id_token"] = jwtSigner.sign(claims);
                         }
                         res->set("Content-Type", "application/json").send(result.dump());
                     }));
            app.post("/oauth2/introspect", safe([this](const Navigation&, const auto& req, const auto& res) {
                         auto fields = parseBody(req->body);
                         require(req->get("Authorization") == "Bearer " + fields["token"], "Bearer authentication required");
                         Json result = {{"active", false}};
                         try {
                             const auto claims = verifiedToken(fields["token"], fields["client_id"]);
                             result = {{"active", true},
                                       {"sub", claims.subject},
                                       {"sid", claims.sessionId},
                                       {"mfa_verified", claims.mfaVerified}};
                         } catch (const std::exception&) {
                         }
                         res->set("Content-Type", "application/json").send(result.dump());
                     }));
            app.get("/oauth2/userinfo", safe([this](const Navigation&, const auto& req, const auto& res) {
                        const auto header = req->get("Authorization");
                        require(header.starts_with("Bearer "), "Bearer token required");
                        const auto token = header.substr(7);
                        const auto first = token.find('.'), second = token.find('.', first + 1);
                        require(first != std::string::npos && second != std::string::npos, "Invalid token");
                        const auto audience =
                            Json::parse(decodeBase64Url(token.substr(first + 1, second - first - 1))).at("aud").template get<std::string>();
                        const auto claims = verifiedToken(token, audience);
                        require(std::find(claims.scopes.begin(), claims.scopes.end(), "openid") != claims.scopes.end(),
                                "OpenID scope required");
                        Json result = {{"sub", claims.subject}};
                        if (std::find(claims.scopes.begin(), claims.scopes.end(), "profile") != claims.scopes.end()) {
                            result["preferred_username"] = claims.username;
                        }
                        if (std::find(claims.scopes.begin(), claims.scopes.end(), "email") != claims.scopes.end()) {
                            result["email"] = claims.email;
                        }
                        res->set("Content-Type", "application/json").send(result.dump());
                    }));

            // ── GET /.well-known/jwks.json ────────────────────────────────────────────
            // Publishes the RS256 public key as a JWK Set so relying parties can fetch
            // and rotate the verification key automatically instead of receiving the
            // public key out of band.
            app.get("/.well-known/jwks.json", safe([this](const Navigation&, const auto&, const auto& res) {
                        res->set("Content-Type", "application/json")
                            .set("Cache-Control", "public,max-age=3600")
                            .set("Access-Control-Allow-Origin", "*")
                            .send(jwksDocument);
                    }));

            // ── GET /.well-known/openid-configuration ─────────────────────────────────
            // OpenID Connect discovery document, so standard OAuth 2.0 / OIDC clients can
            // configure themselves from the issuer URL alone.
            app.get("/.well-known/openid-configuration", safe([this](const Navigation&, const auto&, const auto& res) {
                        json d;
                        d["issuer"] = config.issuer;
                        d["authorization_endpoint"] = config.issuer + "/oauth2/authorize";
                        d["token_endpoint"] = config.issuer + "/oauth2/token";
                        d["userinfo_endpoint"] = config.issuer + "/oauth2/userinfo";
                        d["jwks_uri"] = config.issuer + "/.well-known/jwks.json";
                        d["response_types_supported"] = json::array({"code"});
                        d["grant_types_supported"] = json::array({"authorization_code", "refresh_token"});
                        d["subject_types_supported"] = json::array({"public"});
                        d["id_token_signing_alg_values_supported"] = json::array({"RS256"});
                        d["token_endpoint_auth_methods_supported"] = json::array({"none"});
                        d["code_challenge_methods_supported"] = json::array({"S256"});
                        d["acr_values_supported"] = json::array({"urn:snodec:acr:mfa"});
                        d["scopes_supported"] = json::array({"openid", "profile", "email"});
                        d["claims_supported"] =
                            json::array({"sub", "iss", "aud", "exp", "iat", "username", "email", "mfa_verified", "acr"});
                        res->set("Content-Type", "application/json")
                            .set("Cache-Control", "public,max-age=3600")
                            .set("Access-Control-Allow-Origin", "*")
                            .send(d.dump());
                    }));

            // ── GET /health ───────────────────────────────────────────────────────────
            app.get("/health", safe([this](const Navigation&, const auto&, const auto& res) {
                        json h;
                        h["status"] = "ok";
                        h["service"] = "snodec-idp";
                        h["version"] = AUTH_VERSION;
                        h["revision"] = AUTH_REVISION;
                        res->set("Content-Type", "application/json").send(h.dump());
                    }));

            app.get("/auth/federated/google", safe([this](const Navigation& navigation, const auto& req, const auto& res) {
                        require(!config.googleClientId.empty() && !config.googleClientSecret.empty(), "Google login is disabled");
                        auto context = store.flow(req->cookie("auth_flow"));
                        context.erase("sid");
                        context.erase("mfa_verified");
                        context.erase("user_id");
                        context.erase("enrollment");
                        context.erase("secret");
                        context["account_client"] = navigation.clientId;
                        context["account_return"] = navigation.target;
                        context["provider_state"] = randomToken();
                        context["provider_nonce"] = randomToken();
                        context["provider_verifier"] = randomToken();
                        startFlow(req, res, context);
                        res->redirect("https://accounts.google.com/o/oauth2/v2/auth?" +
                                      formEncode({{"client_id", config.googleClientId},
                                                  {"redirect_uri", config.issuer + "/auth/federated/google/callback"},
                                                  {"response_type", "code"},
                                                  {"scope", "openid email profile"},
                                                  {"state", context.at("provider_state")},
                                                  {"nonce", context.at("provider_nonce")},
                                                  {"code_challenge", sha256(context.at("provider_verifier"))},
                                                  {"code_challenge_method", "S256"}}));
                    }));
            app.get("/auth/federated/google/callback",
                    safe([this]([[maybe_unused]] const Navigation&, [[maybe_unused]] const auto& req, [[maybe_unused]] const auto& res) {
                        require(!config.googleClientId.empty() && !config.googleClientSecret.empty(), "Google login is disabled");
                        const auto flowToken = req->cookie("auth_flow");
                        auto context = store.flow(flowToken);
                        require(!req->query("code").empty() && !req->query("state").empty() &&
                                    context.at("provider_state") == req->query("state"),
                                "Invalid federation transaction");
                        const Navigation navigation{context.value("account_client", std::string()),
                                                    context.value("account_return", std::string())};
                        if (!navigation.target.empty()) {
                            store.accountReturn(navigation.clientId, navigation.target);
                        }
                        context.erase("account_client");
                        context.erase("account_return");
                        context.erase("provider_state");
                        store.save(flowToken, context);
                        const auto body = formEncode({{"client_id", config.googleClientId},
                                                      {"client_secret", config.googleClientSecret},
                                                      {"code", req->query("code")},
                                                      {"code_verifier", context.at("provider_verifier")},
                                                      {"redirect_uri", config.issuer + "/auth/federated/google/callback"},
                                                      {"grant_type", "authorization_code"}});
                        httpExchange(
                            "https://oauth2.googleapis.com/token",
                            "POST",
                            body,
                            {{"Content-Type", "application/x-www-form-urlencoded"}},
                            [this, owner = shared_from_this(), req, res, context, flowToken, navigation](HttpResult response) {
                                try {
                                    require(response.status == 200, "Provider exchange failed");
                                    const auto token = Json::parse(response.body).at("id_token").template get<std::string>();
                                    httpExchange(
                                        "https://www.googleapis.com/oauth2/v3/certs",
                                        "GET",
                                        "",
                                        {},
                                        [this, owner = shared_from_this(), req, res, context, flowToken, token, navigation](
                                            HttpResult keys) mutable {
                                            try {
                                                require(keys.status == 200 &&
                                                            store.flow(flowToken).at("provider_nonce") == context.at("provider_nonce"),
                                                        "Expired provider transaction");
                                                const auto identity = googleIdentity(
                                                    token, Json::parse(keys.body), config.googleClientId, context.at("provider_nonce"));
                                                const auto subject = identity.at("sub").template get<std::string>();
                                                std::string user;
                                                bool mfa = false;
                                                require(db.query("SELECT user.id,user.totp_enabled FROM federated_identity JOIN user ON "
                                                                 "user.id=federated_identity.user_id WHERE provider='google' AND subject=?",
                                                                 {subject},
                                                                 [&](const auto& row) {
                                                                     user = row.get(0);
                                                                     mfa = row.get(1) == "1";
                                                                 }),
                                                        "Identity lookup failed");
                                                if (user.empty()) {
                                                    const auto email = identity.at("email").template get<std::string>();
                                                    require(email.size() <= 254 && email.find_first_of("\r\n") == std::string::npos,
                                                            "Invalid provider email");
                                                    store.execute("BEGIN IMMEDIATE");
                                                    try {
                                                        // A unique-email collision deliberately fails; email is not an account-linking
                                                        // credential.
                                                        store.execute("INSERT INTO user(username,email,password_hash,password_salt) "
                                                                      "VALUES(?,?,'$federated$google$','')",
                                                                      {"google_" + sha256(subject).substr(0, 24), email});
                                                        user = std::to_string(db.lastInsertRowid());
                                                        store.execute(
                                                            "INSERT INTO federated_identity(provider,subject,user_id) VALUES('google',?,?)",
                                                            {subject, user});
                                                        store.execute("COMMIT");
                                                    } catch (...) {
                                                        db.exec("ROLLBACK");
                                                        throw;
                                                    }
                                                }
                                                context.erase("provider_nonce");
                                                context.erase("provider_verifier");
                                                context["user_id"] = user;
                                                store.save(flowToken, context);
                                                if (mfa) {
                                                    res->send(mfaPage(navigation, sha256(req->cookie("auth_flow"))));
                                                } else {
                                                    finishLogin(navigation, req, res, user, false);
                                                }
                                            } catch (const std::exception&) {
                                                res->status(401).send("Google authentication failed");
                                            }
                                        });
                                } catch (const std::exception&) {
                                    res->status(401).send("Google authentication failed");
                                }
                            });
                    }));
        }
    };
} // namespace

namespace snodec::auth {
    IdpMiddleware::IdpMiddleware(IdpConfig config) {
        std::make_shared<IdpState>(std::move(config))->mount(*this);
    }
} // namespace snodec::auth
