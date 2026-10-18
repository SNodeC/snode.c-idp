#include "AuthStore.h"

#include "SecretEncryptor.h"

#include <sstream>

namespace snodec::auth {
    using database::sqlite::SqliteDatabase;
    class Transaction {
    public:
        explicit Transaction(SqliteDatabase& db)
            : db_(db) {
            require(db_.exec("BEGIN IMMEDIATE"), "Database transaction failed");
        }
        ~Transaction() {
            if (!committed_) {
                db_.exec("ROLLBACK");
            }
        }
        void commit() {
            require(db_.exec("COMMIT"), "Database commit failed");
            committed_ = true;
        }

    private:
        SqliteDatabase& db_;
        bool committed_ = false;
    };

    AuthStore::AuthStore(SqliteDatabase& db, Json clients)
        : db_(db)
        , clients_(std::move(clients)) {
        require(clients_.is_object(), "IDP_CLIENTS must be a JSON object mapping client IDs to callback arrays");
        for (const auto& [id, callbacks] : clients_.items()) {
            require(!id.empty() && callbacks.is_array() && !callbacks.empty(), "Invalid client registration");
            for (const auto& callback : callbacks) {
                const auto url = callback.get<std::string>();
                endpoint(url);
            }
        }
    }

    void AuthStore::execute(const std::string& sql, const std::vector<std::string>& args) {
        require(db_.exec(sql, args), "Database operation failed");
    }

    Json AuthStore::authorization(const Json& input) const {
        const auto client = input.value("client_id", std::string());
        const auto redirect = input.value("redirect_uri", std::string());
        require(clients_.contains(client) &&
                    std::find(clients_.at(client).begin(), clients_.at(client).end(), redirect) != clients_.at(client).end(),
                "Unregistered client or redirect URI");
        const auto challenge = input.value("code_challenge", std::string());
        require(input.value("response_type", std::string()) == "code" && input.value("code_challenge_method", std::string()) == "S256" &&
                    challenge.size() == 43 && decodeBase64Url(challenge).size() == 32,
                "Invalid authorization request");
        Json context = Json::object();
        for (const auto* key : {"client_id", "redirect_uri", "state", "scope", "nonce", "code_challenge", "code_challenge_method"}) {
            const auto value = input.value(key, std::string());
            require(value.size() <= 2048, "Authorization parameter too long");
            context[key] = value;
        }
        std::istringstream scopes(context.at("scope").get<std::string>());
        std::string scope;
        while (scopes >> scope) {
            require(scope == "openid" || scope == "profile" || scope == "email", "Unsupported scope");
        }
        require(!context.at("state").get<std::string>().empty(), "Missing state");
        return context;
    }

    std::string AuthStore::begin(const Json& context) {
        execute("DELETE FROM auth_flow WHERE expires_at <= ?", {std::to_string(epochSeconds())});
        const auto token = randomToken();
        execute("INSERT INTO auth_flow(token_hash,context,expires_at) VALUES(?,?,?)",
                {sha256(token), context.dump(), std::to_string(epochSeconds() + 600)});
        return token;
    }

    Json AuthStore::flow(const std::string& browserToken) {
        Json context;
        require(!browserToken.empty() && db_.query("SELECT context FROM auth_flow WHERE token_hash=? AND expires_at>?",
                                                   {sha256(browserToken), std::to_string(epochSeconds())},
                                                   [&](const SqliteDatabase::Row& row) {
                                                       context = Json::parse(row.get(0));
                                                   }),
                "Missing login transaction");
        require(context.is_object(), "Login transaction expired; start again");
        return context;
    }

    Json AuthStore::formFlow(const std::string& browserToken, const std::string& transaction) {
        require(!browserToken.empty() && transaction == sha256(browserToken), "Stale login form");
        return flow(browserToken);
    }

    void AuthStore::save(const std::string& browserToken, const Json& context) {
        execute("UPDATE auth_flow SET context=? WHERE token_hash=? AND expires_at>?",
                {context.dump(), sha256(browserToken), std::to_string(epochSeconds())});
        require(db_.changedRows() == 1, "Login transaction expired");
    }

    Json AuthStore::complete(const std::string& browserToken, const std::string& userId, bool mfaVerified, bool enrollment) {
        Transaction transaction(db_);
        auto context = flow(browserToken);
        require(context.value("user_id", std::string()) == userId && !userId.empty(), "Primary authentication required");
        if (context.contains("sid")) {
            require(active(context.at("sid"), userId, context.value("mfa_verified", mfaVerified)), "Session revoked");
        }
        if (enrollment) {
            require(mfaVerified && context.value("enrollment", false) && context.contains("secret"), "Enrollment not authorized");
            execute("UPDATE user SET totp_secret=?,totp_enabled=1,activated=1 WHERE id=? AND totp_enabled=0",
                    {context.at("secret"), userId});
            require(db_.changedRows() == 1, "Enrollment already completed");
            context.erase("sid");
        }
        std::string token;
        if (!context.contains("sid")) {
            token = randomToken();
            execute("INSERT INTO session(token,user_id,mfa_verified,expires_at) VALUES(?,?,?,datetime('now','+24 hours'))",
                    {sha256(token), userId, mfaVerified ? "1" : "0"});
            context["sid"] = std::to_string(db_.lastInsertRowid());
        }
        context["mfa_verified"] = mfaVerified;
        context.erase("secret");
        const auto code = randomToken();
        if (!context.value("client_id", std::string()).empty()) {
            auto request = context;
            request["response_type"] = "code";
            authorization(request);
            execute("INSERT INTO auth_code(code,session_id,context,expires_at) VALUES(?,?,?,?)",
                    {sha256(code), context.at("sid").get<std::string>(), context.dump(), std::to_string(epochSeconds() + 120)});
        }
        execute("DELETE FROM auth_flow WHERE token_hash=?", {sha256(browserToken)});
        transaction.commit();
        context["session_cookie"] = token;
        context["code"] = code;
        return context;
    }

    Json AuthStore::redeem(const Json& parameters) {
        Transaction transaction(db_);
        const auto kind = parameters.value("grant_type", std::string());
        const bool refresh = kind == "refresh_token";
        require(refresh || kind == "authorization_code", "Unsupported grant");
        const auto credential = parameters.value(refresh ? "refresh_token" : "code", std::string());
        require(!credential.empty(), "Missing credential");
        Json context;
        bool used = false;
        const std::string sql = refresh ? "SELECT context,used FROM refresh_token WHERE token_hash=? AND expires_at>?"
                                        : "SELECT context,0 FROM auth_code WHERE code=? AND expires_at>?";
        require(db_.query(sql,
                          {sha256(credential), std::to_string(epochSeconds())},
                          [&](const SqliteDatabase::Row& row) {
                              context = Json::parse(row.get(0));
                              used = row.get(1) == "1";
                          }),
                "Grant lookup failed");
        require(context.is_object() && context.at("client_id") == parameters.value("client_id", std::string()), "Invalid grant");
        if (used) {
            execute("DELETE FROM session WHERE id=?", {context.at("sid").get<std::string>()});
            transaction.commit();
            throw std::runtime_error("Refresh token replay");
        }
        require(active(context.at("sid"), context.at("user_id"), context.at("mfa_verified")), "Session revoked");
        if (!refresh) {
            const auto verifier = parameters.value("code_verifier", std::string());
            require(verifier.size() >= 43 && verifier.size() <= 128 &&
                        verifier.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~") ==
                            std::string::npos &&
                        context.at("code_challenge") == sha256(verifier) &&
                        context.at("redirect_uri") == parameters.value("redirect_uri", std::string()),
                    "Invalid PKCE or callback");
            execute("DELETE FROM auth_code WHERE code=?", {sha256(credential)});
        } else {
            execute("UPDATE refresh_token SET used=1 WHERE token_hash=? AND used=0", {sha256(credential)});
        }
        require(db_.changedRows() == 1, "Credential already consumed");
        const auto replacement = randomToken();
        execute("INSERT INTO refresh_token(token_hash,session_id,context,expires_at) VALUES(?,?,?,?)",
                {sha256(replacement), context.at("sid"), context.dump(), std::to_string(epochSeconds() + 86400)});
        transaction.commit();
        context["refresh_token"] = replacement;
        return context;
    }

    Json AuthStore::session(const std::string& cookie) {
        Json session;
        if (!cookie.empty()) {
            require(db_.query("SELECT id,user_id,mfa_verified FROM session WHERE token=? AND expires_at>CURRENT_TIMESTAMP",
                              {sha256(cookie)},
                              [&](const SqliteDatabase::Row& row) {
                                  session = {{"sid", row.get(0)}, {"user_id", row.get(1)}, {"mfa_verified", row.get(2) == "1"}};
                              }),
                    "Session lookup failed");
        }
        return session;
    }

    bool AuthStore::active(const std::string& id, const std::string& userId, bool mfa) {
        bool active = false;
        require(db_.query("SELECT 1 FROM session WHERE id=? AND user_id=? AND mfa_verified=? AND expires_at>CURRENT_TIMESTAMP",
                          {id, userId, mfa ? "1" : "0"},
                          [&](const SqliteDatabase::Row&) {
                              active = true;
                          }),
                "Session lookup failed");
        return active;
    }

    void AuthStore::migrateTotp(const std::string& keyPath) {
        const auto probe = SecretEncryptor::encrypt("key-check", keyPath);
        require(SecretEncryptor::decrypt(probe, keyPath) == "key-check", "Invalid TOTP encryption key");
        Transaction transaction(db_);
        std::vector<std::pair<std::string, std::string>> records;
        require(db_.query("SELECT id,totp_secret FROM user WHERE totp_secret IS NOT NULL AND totp_secret<>''",
                          [&](const auto& row) {
                              records.emplace_back(row.get(0), row.get(1));
                          }),
                "Cannot read TOTP records");
        for (const auto& [id, secret] : records) {
            if (SecretEncryptor::isEncrypted(secret)) {
                SecretEncryptor::decrypt(secret, keyPath);
            } else {
                require(secret.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") == std::string::npos, "Invalid legacy TOTP secret");
                execute("UPDATE user SET totp_secret=? WHERE id=?", {SecretEncryptor::encrypt(secret, keyPath), id});
            }
        }
        transaction.commit();
    }

    void AuthStore::requestReset(const std::string& email, const std::function<void(const std::string&, const std::string&)>& deliver) {
        std::string id, address;
        require(db_.query("SELECT id,email FROM user WHERE email=? AND activated=1",
                          {email},
                          [&](const auto& row) {
                              id = row.get(0);
                              address = row.get(1);
                          }),
                "Reset unavailable");
        if (!id.empty()) {
            const auto token = randomToken();
            try {
                execute("DELETE FROM password_reset_tokens WHERE user_id=?", {id});
                execute("INSERT INTO password_reset_tokens(token,user_id,expires_at) VALUES(?,?,datetime('now','+15 minutes'))",
                        {sha256(token), id});
                deliver(address, token);
            } catch (const std::exception&) {
                execute("DELETE FROM password_reset_tokens WHERE user_id=?", {id});
            }
        }
    }

    void AuthStore::resetPassword(const std::string& token, const std::string& passwordHash) {
        Transaction transaction(db_);
        std::string id;
        require(db_.query("SELECT user_id FROM password_reset_tokens WHERE token=? AND used=0 AND expires_at>datetime('now')",
                          {sha256(token)},
                          [&](const auto& row) {
                              id = row.get(0);
                          }),
                "Reset unavailable");
        require(!id.empty(), "Invalid reset token");
        execute("DELETE FROM password_reset_tokens WHERE token=?", {sha256(token)});
        require(db_.changedRows() == 1, "Reset already consumed");
        execute("UPDATE user SET password_hash=?,password_salt='' WHERE id=?", {passwordHash, id});
        transaction.commit();
    }

} // namespace snodec::auth
