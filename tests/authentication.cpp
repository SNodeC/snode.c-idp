#include "auth/AuthStore.h"
#include "auth/IdpMiddleware.h"
#include "auth/JwtAuthMiddleware.h"
#include "auth/JwtSigner.h"
#include "auth/OAuth2CallbackHandler.h"
#include "auth/SecretEncryptor.h"
#include "express/Request.h"
#include "web/http/server/Request.h"

#include <fstream>
#include <functional>
#include <iostream>
#include <openssl/pem.h>

using namespace snodec::auth;
using snodec::database::sqlite::SqliteDatabase;

static void rejects(const std::function<void()>& operation, const std::string& reason = "") {
    bool rejected = false;
    try {
        operation();
    } catch (const std::exception& error) {
        rejected = reason.empty() || std::string(error.what()).find(reason) != std::string::npos;
    }
    require(rejected, "Expected rejection: " + reason);
}

static std::string privateKey() {
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr), EVP_PKEY_CTX_free);
    require(ctx && EVP_PKEY_keygen_init(ctx.get()) == 1 && EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), 2048) == 1, "Key generation failed");
    EVP_PKEY* raw = nullptr;
    require(EVP_PKEY_keygen(ctx.get(), &raw) == 1, "Key generation failed");
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(raw, EVP_PKEY_free);
    std::unique_ptr<BIO, decltype(&BIO_free)> output(BIO_new(BIO_s_mem()), BIO_free);
    require(output && PEM_write_bio_PrivateKey(output.get(), key.get(), nullptr, nullptr, 0, nullptr, nullptr) == 1, "Key export failed");
    char* bytes = nullptr;
    const auto length = BIO_get_mem_data(output.get(), &bytes);
    return std::string(bytes, static_cast<size_t>(length));
}

static Json form(const std::string& body) {
    Json fields = Json::object();
    size_t offset = 0;
    while (offset < body.size()) {
        const auto end = body.find('&', offset);
        const auto part = body.substr(offset, end == std::string::npos ? body.size() - offset : end - offset);
        const auto split = part.find('=');
        const auto decode = [](const std::string& text) {
            std::string result;
            for (size_t i = 0; i < text.size(); ++i) {
                if (text[i] == '%' && i + 2 < text.size()) {
                    result += static_cast<char>(std::stoi(text.substr(i + 1, 2), nullptr, 16));
                    i += 2;
                } else {
                    result += text[i];
                }
            }
            return result;
        };
        fields[decode(part.substr(0, split))] = decode(part.substr(split + 1));
        offset = end == std::string::npos ? body.size() : end + 1;
    }
    return fields;
}

static void storeTests() {
    SqliteDatabase db(":memory:");
    db.initSchema();
    db.initSchema();
    AuthStore store(db, {{"app", Json::array({"https://app.example/callback"})}});
    for (const auto& target : {"https://app.example/private?x=1&next=%2Fhome", "https://app.example:443/other"}) {
        require(store.accountReturn("app", target) == target, "Registered client return rejected");
    }
    for (const auto& target : {"https://evil.example/private",
                               "https://app.example.evil/private",
                               "https://app.example:444/private",
                               "http://app.example/private",
                               "//app.example/private",
                               "javascript:alert(1)",
                               "https://app.example@evil.example/private",
                               "https://app.example/\\evil",
                               "https://app.example/\n"}) {
        rejects([&] {
            store.accountReturn("app", target);
        });
    }
    rejects([&] {
        store.accountReturn("unknown", "https://app.example/private");
    });
    store.execute("INSERT INTO user(username,email,password_hash,password_salt) VALUES('alice','alice@example.org','hash','')");
    const std::string verifier = randomToken();
    const Json request = {{"response_type", "code"},
                          {"client_id", "app"},
                          {"redirect_uri", "https://app.example/callback"},
                          {"state", "state"},
                          {"nonce", "nonce"},
                          {"scope", "openid profile email"},
                          {"code_challenge", sha256(verifier)},
                          {"code_challenge_method", "S256"}};
    const auto context = store.authorization(request);
    for (const auto& invalid : {Json{{"client_id", "other"}},
                                Json{{"redirect_uri", "http://192.168.1.1/auth/callback"}},
                                Json{{"code_challenge_method", "plain"}},
                                Json{{"code_challenge", "bad"}}}) {
        auto changed = request;
        changed.update(invalid);
        rejects([&] {
            store.authorization(changed);
        });
    }
    auto pending = store.begin(context);
    require(store.formFlow(pending, sha256(pending)) == context, "Valid form rejected");
    rejects([&] {
        store.formFlow(pending, sha256(randomToken()));
    });
    rejects([&] {
        store.formFlow("", "");
    });
    rejects([&] {
        store.complete(pending, "1", true);
    });
    auto proven = context;
    proven["user_id"] = "1";
    store.save(pending, proven);
    rejects([&] {
        store.complete(pending, "2", true);
    });
    rejects([&] {
        store.flow(randomToken());
    });
    const auto completed = store.complete(pending, "1", true);
    rejects([&] {
        store.complete(pending, "1", true);
    });
    require(store.session(completed.at("session_cookie")).at("mfa_verified") == true, "Session MFA missing");
    Json redemption = {{"grant_type", "authorization_code"},
                       {"code", completed.at("code")},
                       {"client_id", "app"},
                       {"redirect_uri", "https://app.example/callback"},
                       {"code_verifier", verifier}};
    auto wrong = redemption;
    wrong["redirect_uri"] = "https://evil.example/";
    rejects([&] {
        store.redeem(wrong);
    });
    wrong = redemption;
    wrong["code_verifier"] = randomToken();
    rejects([&] {
        store.redeem(wrong);
    });
    const auto grant = store.redeem(redemption);
    rejects([&] {
        store.redeem(redemption);
    });
    require(grant.at("nonce") == "nonce" && grant.at("mfa_verified") == true, "Grant context changed");
    Json refresh = {{"grant_type", "refresh_token"}, {"refresh_token", grant.at("refresh_token")}, {"client_id", "app"}};
    wrong = refresh;
    wrong["client_id"] = "other";
    rejects([&] {
        store.redeem(wrong);
    });
    const auto rotated = store.redeem(refresh);
    rejects([&] {
        store.redeem(refresh);
    });
    require(!store.active(grant.at("sid"), "1", true), "Refresh replay did not revoke session");
    refresh["refresh_token"] = rotated.at("refresh_token");
    rejects([&] {
        store.redeem(refresh);
    });
    const auto initial = store.complete(store.begin(proven), "1", true);
    auto ssoContext = proven;
    ssoContext["sid"] = initial.at("sid");
    const auto sso = store.complete(store.begin(ssoContext), "1", true);
    require(sso.at("sid") == initial.at("sid") && sso.at("session_cookie") == "", "SSO replaced the browser session");
    store.execute("DELETE FROM session WHERE token=?", {sha256(initial.at("session_cookie"))});
    for (const auto& login : {initial, sso}) {
        require(!store.active(login.at("sid"), "1", true), "Logout retained SSO authority");
        redemption["code"] = login.at("code");
        rejects([&] {
            store.redeem(redemption);
        });
    }
    rejects([&] {
        store.complete(store.begin(ssoContext), "1", true);
    });
    for (const auto* change : {"password_hash='new'", "totp_enabled=1", "totp_secret='changed'"}) {
        pending = store.begin(proven);
        const auto session = store.complete(pending, "1", true);
        const auto otherFlow = store.begin(proven);
        store.execute(std::string("UPDATE user SET ") + change + " WHERE id=1");
        require(!store.active(session.at("sid"), "1", true), "Account update retained session");
        rejects([&] {
            store.flow(otherFlow);
        });
    }
    store.execute("UPDATE user SET totp_enabled=0,totp_secret=NULL WHERE id=1");
    auto enrollment = proven;
    enrollment["enrollment"] = true;
    enrollment["secret"] = "encrypted-fixture";
    const auto oldSession = store.complete(store.begin(proven), "1", false);
    auto badEnrollment = enrollment;
    badEnrollment["redirect_uri"] = "https://evil.example/";
    rejects([&] {
        store.complete(store.begin(badEnrollment), "1", true, true);
    });
    require(store.active(oldSession.at("sid"), "1", false), "Failed enrollment did not roll back revocation");
    auto sessionEnrollment = enrollment;
    sessionEnrollment["sid"] = oldSession.at("sid");
    sessionEnrollment["mfa_verified"] = false;
    const auto enrolled = store.complete(store.begin(sessionEnrollment), "1", true, true);
    require(!store.active(oldSession.at("sid"), "1", false) && store.active(enrolled.at("sid"), "1", true),
            "Enrollment session transition failed");
    rejects([&] {
        store.complete(store.begin(enrollment), "1", true, true);
    });
    rejects([&] {
        store.complete(store.begin(sessionEnrollment), "1", true, true);
    });
    pending = store.begin(proven);
    store.execute("UPDATE auth_flow SET expires_at=0");
    rejects([&] {
        store.complete(pending, "1", true);
    });
    pending = store.begin(proven);
    const auto session = store.complete(pending, "1", false);
    store.execute("DELETE FROM user WHERE id=1");
    require(!store.active(session.at("sid"), "1", false), "Account deletion retained session");
    require(store.session(session.at("session_cookie")).is_null(), "Deleted session accepted");
    rejects([&] {
        db.query("SELECT 1", [](const auto&) {
            throw std::runtime_error("callback failure");
        });
    });
    store.execute("BEGIN IMMEDIATE");
    store.execute("ROLLBACK");
}

static void resetAndMigrationTests() {
    SqliteDatabase db(":memory:");
    // A pre-hardening database with a session incorrectly marked as MFA-verified.
    require(db.exec("CREATE TABLE user(id INTEGER PRIMARY KEY,username TEXT UNIQUE,email TEXT UNIQUE,password_hash TEXT,password_salt "
                    "TEXT,totp_secret TEXT,totp_enabled INTEGER DEFAULT 0,created_at TEXT DEFAULT CURRENT_TIMESTAMP,updated_at TEXT "
                    "DEFAULT CURRENT_TIMESTAMP)"),
            "Fixture failed");
    require(db.exec("INSERT INTO user(id,username,email,password_hash,password_salt) VALUES(1,'alice','alice@example.org','hash','')"),
            "Fixture failed");
    require(db.exec("CREATE TABLE session(id INTEGER PRIMARY KEY,token TEXT,user_id INTEGER,mfa_verified INTEGER,expires_at TEXT)"),
            "Fixture failed");
    require(db.exec("INSERT INTO session VALUES(1,'old-session',1,1,datetime('now','+1 day'))"), "Fixture failed");
    db.initSchema();
    AuthStore store(db, Json::object());
    require(store.session("old-session").is_null(), "Legacy session retained authority");
    const auto context = Json{{"user_id", "1"}};
    const auto session = store.complete(store.begin(context), "1", true);
    std::string delivered;
    bool unexpectedDelivery = false;
    store.requestReset("unknown@example.org", [&](const auto&, const auto&) {
        unexpectedDelivery = true;
    });
    require(!unexpectedDelivery, "Unknown account received reset mail");
    store.requestReset("alice@example.org", [&](const auto& email, const auto& token) {
        require(email == "alice@example.org", "Reset sent to wrong address");
        delivered = token;
    });
    require(!delivered.empty(), "No reset delivered");
    bool plaintext = false;
    db.query("SELECT token FROM password_reset_tokens", [&](const auto& row) {
        plaintext = row.get(0) == delivered;
    });
    require(!plaintext, "Reset credential stored in plaintext");
    store.resetPassword(delivered, "replacement");
    rejects([&] {
        store.resetPassword(delivered, "replacement");
    });
    require(!store.active(session.at("sid"), "1", true), "Reset retained active session");
    store.requestReset("alice@example.org", [&](const auto&, const auto& token) {
        delivered = token;
        throw std::runtime_error("delivery failed");
    });
    rejects([&] {
        store.resetPassword(delivered, "replacement");
    });
    store.requestReset("alice@example.org", [&](const auto&, const auto& token) {
        delivered = token;
    });
    store.execute("UPDATE password_reset_tokens SET expires_at=datetime('now','-1 minute')");
    rejects([&] {
        store.resetPassword(delivered, "replacement");
    });

    store.requestReset("alice@example.org", [&](const auto&, const auto& token) {
        delivered = token;
    });
    store.execute("CREATE TRIGGER fail_password BEFORE UPDATE OF password_hash ON user BEGIN SELECT RAISE(ABORT,'fixture'); END");
    rejects([&] {
        store.resetPassword(delivered, "rollback-test");
    });
    store.execute("DROP TRIGGER fail_password");
    store.resetPassword(delivered, "rollback-test");
    const std::string keyPath = "test-totp.key";
    {
        std::ofstream file(keyPath, std::ios::binary);
        file << std::string(32, 'K');
    }
    store.execute("UPDATE user SET totp_secret='GEZDGNBVGY3TQOJQ' WHERE id=1");
    rejects([&] {
        store.migrateTotp("missing-key");
    });
    store.execute(
        "INSERT INTO user(username,email,password_hash,password_salt,totp_secret) VALUES('bad','bad@example.org','hash','','not-base32')");
    rejects([&] {
        store.migrateTotp(keyPath);
    });
    std::string unchanged;
    db.query("SELECT totp_secret FROM user WHERE id=1", [&](const auto& row) {
        unchanged = row.get(0);
    });
    require(unchanged == "GEZDGNBVGY3TQOJQ", "Partial encryption migration was committed");
    store.execute("DELETE FROM user WHERE username='bad'");
    store.migrateTotp(keyPath);
    std::string encrypted;
    db.query("SELECT totp_secret FROM user WHERE id=1", [&](const auto& row) {
        encrypted = row.get(0);
    });
    require(SecretEncryptor::isEncrypted(encrypted) && SecretEncryptor::decrypt(encrypted, keyPath) == "GEZDGNBVGY3TQOJQ",
            "TOTP migration failed");
    {
        std::ofstream file(keyPath, std::ios::binary);
        file << std::string(32, 'X');
    }
    rejects([&] {
        store.migrateTotp(keyPath);
    });
    {
        std::ofstream file(keyPath, std::ios::binary);
        file << std::string(33, 'X');
    }
    rejects([&] {
        SecretEncryptor::encrypt("secret", keyPath);
    });
    std::remove(keyPath.c_str());
}

static std::string signedFixture(const std::string& key, const Json& header, const Json& payload) {
    const auto input = base64Url(header.dump()) + "." + base64Url(payload.dump());
    std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new_mem_buf(key.data(), static_cast<int>(key.size())), BIO_free);
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> rsa(PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr), EVP_PKEY_free);
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    require(ctx && rsa && EVP_DigestSignInit(ctx.get(), nullptr, EVP_sha256(), nullptr, rsa.get()) == 1, "Fixture signing failed");
    size_t length = 0;
    require(EVP_DigestSign(ctx.get(), nullptr, &length, reinterpret_cast<const unsigned char*>(input.data()), input.size()) == 1,
            "Fixture signing failed");
    std::string signature(length, '\0');
    require(EVP_DigestSign(ctx.get(),
                           reinterpret_cast<unsigned char*>(signature.data()),
                           &length,
                           reinterpret_cast<const unsigned char*>(input.data()),
                           input.size()) == 1,
            "Fixture signing failed");
    signature.resize(length);
    return input + "." + base64Url(signature);
}

static void googleTests() {
    const auto key = privateKey();
    JwtSigner signer("https://accounts.google.com", key);
    const auto jwks = Json::parse(signer.jwks());
    const Json header = {{"alg", "RS256"}, {"kid", jwks.at("keys").at(0).at("kid")}};
    const Json identity = {{"iss", "https://accounts.google.com"},
                           {"aud", "google-client"},
                           {"sub", "stable-subject"},
                           {"nonce", "expected"},
                           {"email_verified", true},
                           {"email", "alice@example.org"},
                           {"exp", epochSeconds() + 300},
                           {"iat", epochSeconds()}};
    require(googleIdentity(signedFixture(key, header, identity), jwks, "google-client", "expected").at("sub") == "stable-subject",
            "Google identity rejected");
    for (const auto& invalid : {Json{{"iss", "https://evil.example"}},
                                Json{{"aud", "other"}},
                                Json{{"nonce", "wrong"}},
                                Json{{"exp", 0}},
                                Json{{"email_verified", false}},
                                Json{{"email_verified", "true"}},
                                Json{{"azp", "other"}}}) {
        auto changed = identity;
        changed.update(invalid);
        rejects([&] {
            googleIdentity(signedFixture(key, header, changed), jwks, "google-client", "expected");
        });
    }
    auto wrong = header;
    wrong["kid"] = "unknown";
    rejects([&] {
        googleIdentity(signedFixture(key, wrong, identity), jwks, "google-client", "expected");
    });
    rejects([&] {
        googleIdentity(signedFixture(privateKey(), header, identity), jwks, "google-client", "expected");
    });
}

struct TestResponse {
    int code = 200;
    std::string body, location;
    std::map<std::string, std::string> headers, cookies;
    TestResponse& status(int value) {
        code = value;
        return *this;
    }
    TestResponse& set(const std::string& key, const std::string& value) {
        headers[key] = value;
        return *this;
    }
    void send(const std::string& value) {
        body = value;
    }
    void redirect(const std::string& value) {
        code = 302;
        location = value;
    }
    TestResponse& cookie(const std::string& name, const std::string& value, const std::map<std::string, std::string>&) {
        cookies[name] = value;
        return *this;
    }
};

static void tokenAndClientTests() {
    require(formEncode(Json::object()).empty(), "Empty form must stay empty");
    require(formEncode(Json{{"a&=", "x+y z"}, {"empty", ""}}) == "a%26%3D=x%2By%20z&empty=", "Form escaping or separators changed");
    rejects(
        [] {
            formEncode(Json{{"invalid", 1}});
        },
        "Form value must be a string");
    const auto key = privateKey();
    JwtSigner signer("https://idp.example", key);
    JwtVerifier verifier("https://idp.example", "app", signer.publicKey());
    JwtClaims claims;
    claims.subject = "1";
    claims.sessionId = "42";
    claims.audience = "app";
    claims.mfaVerified = true;
    claims.username = "Alice \\\" <script> é";
    claims.email = "alice@example.org";
    claims.scopes = {"openid", "profile", "email"};
    claims.expiresAt = std::chrono::system_clock::now() + std::chrono::seconds(300);
    auto access = signer.sign(claims);
    JwtClaims verified;
    std::string error;
    require(verifier.verify(access, verified, error) && verified.username == claims.username, "JSON claims roundtrip failed");
    require(!verifier.verify(access, verified, error, "id"), "Access token accepted as ID token");
    auto corrupt = access;
    corrupt[corrupt.size() - 5] = corrupt[corrupt.size() - 5] == 'A' ? 'B' : 'A';
    require(!verifier.verify(corrupt, verified, error), "Forged token accepted");
    claims.audience = "other";
    require(!verifier.verify(signer.sign(claims), verified, error), "Wrong audience accepted");
    claims.audience = "app";
    claims.expiresAt = std::chrono::system_clock::now() - std::chrono::seconds(1);
    require(!verifier.verify(signer.sign(claims), verified, error), "Expired token accepted");
    claims.expiresAt = std::chrono::system_clock::now() + std::chrono::seconds(300);
    const auto header = Json::parse(decodeBase64Url(access.substr(0, access.find('.'))));
    require(header.at("kid") == Json::parse(signer.jwks()).at("keys").at(0).at("kid"), "Signing key/JWKS mismatch");

    const auto payload = Json::parse(decodeBase64Url(access.substr(access.find('.') + 1, access.rfind('.') - access.find('.') - 1)));
    for (const auto& invalid : {Json{{"iss", "https://evil.example"}},
                                Json{{"nbf", epochSeconds() + 300}},
                                Json{{"iat", epochSeconds() + 300}},
                                Json{{"exp", "9999999999"}},
                                Json{{"mfa_verified", "true"}},
                                Json{{"scope", "openid"}},
                                Json{{"sid", ""}}}) {
        auto changed = payload;
        changed.update(invalid);
        require(!verifier.verify(signedFixture(key, header, changed), verified, error), "Invalid claim accepted");
    }
    auto badHeader = header;
    badHeader["alg"] = "HS256";
    require(!verifier.verify(signedFixture(key, badHeader, payload), verified, error), "Wrong algorithm accepted");
    require(!verifier.verify("not.a.jwt", verified, error), "Malformed JWT accepted");
    HttpCompletion pending;
    std::string posted;
    HttpExchange transport = [&](const auto&, const auto&, const auto& body, const auto&, HttpCompletion done) {
        posted = body;
        pending = std::move(done);
    };
    auto client =
        std::make_shared<OAuthClient>("https://idp.example", "app", "https://app.example/callback", signer.publicKey(), transport);
    const auto account = client->accountUrl("/private?x=1&next=%2Fhome");
    const auto navigation = form(account.substr(account.find('?') + 1));
    require(account.starts_with("https://idp.example/settings?") && navigation.at("client_id") == "app" &&
                navigation.at("return") == "https://app.example/private?x=1&next=%2Fhome",
            "Account navigation lost destination");
    rejects([&] {
        client->accountUrl("//evil.example/private");
    });
    auto login = client->begin("/private?x=1");
    auto second = client->begin("//evil.example/");
    const auto authorization = form(login.authorizeUrl.substr(login.authorizeUrl.find('?') + 1));
    bool called = false;
    client->complete(login.state, second.state, "code", [&](auto token, auto) {
        called = true;
        require(token.empty(), "Swapped browser accepted");
    });
    require(called && !pending, "Invalid state reached exchange");
    std::string received, target;
    client->complete(login.state, login.state, "code", [&](auto token, auto path) {
        received = token;
        target = path;
    });
    require(static_cast<bool>(pending), "No server-side exchange");
    const auto exchange = form(posted);
    require(exchange.at("redirect_uri") == "https://app.example/callback" &&
                sha256(exchange.at("code_verifier")) == authorization.at("code_challenge").get<std::string>(),
            "PKCE context lost");
    claims.purpose = "id";
    claims.nonce = authorization.at("nonce");
    auto finish = std::move(pending);
    finish({200, Json({{"access_token", access}, {"id_token", signer.sign(claims)}}).dump()});
    require(received == access && target == "/private?x=1", "Valid login failed");
    called = false;
    client->complete(login.state, login.state, "code", [&](auto token, auto) {
        called = true;
        require(token.empty(), "Callback replay accepted");
    });
    require(called, "Replay callback not completed");
    client->complete(second.state, second.state, "code", [&](auto token, auto path) {
        received = token;
        target = path;
    });
    claims.nonce = "wrong";
    finish = std::move(pending);
    finish({200, Json({{"access_token", access}, {"id_token", signer.sign(claims)}}).dump()});
    require(received.empty(), "Nonce mismatch accepted");
    bool accepted = false;
    client->authorize(access, [&](bool ok, auto) {
        accepted = ok;
    });
    require(static_cast<bool>(pending), "Authorization skipped online check");
    finish = std::move(pending);
    finish({200, R"({"active":true,"sub":"1","sid":"42","mfa_verified":true})"});
    require(accepted, "Active session rejected");
    client->authorize(access, [&](bool ok, auto) {
        accepted = ok;
    });
    finish = std::move(pending);
    finish({200, R"({"active":false})"});
    require(!accepted, "Revoked session accepted");
    client->authorize(access, [&](bool ok, auto) {
        accepted = ok;
    });
    finish = std::move(pending);
    finish({});
    require(!accepted, "Unavailable IDP accepted");
    // Exercise the actual browser adapter with a real Express request and an offline response sink.
    middleware::JwtAuthMiddleware middleware(client);
    auto requestBase = std::make_shared<web::http::server::Request>();
    auto request = std::make_shared<express::Request>(requestBase);
    request->method = "GET";
    request->url = "/";
    request->originalUrl = "/private";
    request->cookies["access_token"] = access;
    auto response = std::make_shared<TestResponse>();
    bool next = false;
    middleware(request, response, [&] {
        next = true;
    });
    finish = std::move(pending);
    finish({200, R"({"active":true,"sub":"1","sid":"42","mfa_verified":true})"});
    require(next, "Middleware blocked active session");
    next = false;
    middleware(request, response, [&] {
        next = true;
    });
    finish = std::move(pending);
    finish({200, R"({"active":false})"});
    require(!next && response->code == 302 && response->location.starts_with("https://idp.example/oauth2/authorize?") &&
                response->cookies.contains("access_token") && response->cookies.at("access_token").empty(),
            "Revoked browser session did not restart login and clear the cookie");
    request->method = "POST";
    requestBase->headers["authorization"] = "Basic bogus";
    middleware(request, response, [&] {
        next = true;
    });
    require(!next && !pending && response->code == 403, "Non-bearer header bypassed cookie CSRF check");
    request->method = "GET";
    requestBase->headers.clear();
    request->cookies.clear();
    middleware(request, response, [&] {
        next = true;
    });
    require(response->code == 302 && response->headers.at("Set-Cookie").find("HttpOnly") != std::string::npos,
            "Login redirect missing browser binding");
    for (const auto& failure : {HttpResult{}, HttpResult{400, "error"}, HttpResult{200, "malformed"}, HttpResult{200, "{}"}}) {
        const auto attempt = client->begin("/private");
        client->complete(attempt.state, attempt.state, "code", [&](auto token, auto) {
            received = token;
        });
        finish = std::move(pending);
        finish(failure);
        require(received.empty(), "Invalid exchange accepted");
    }
    const auto callbackLogin = client->begin("/private");
    const auto callbackParameters = form(callbackLogin.authorizeUrl.substr(callbackLogin.authorizeUrl.find('?') + 1));
    request->queries = {{"state", callbackLogin.state}, {"code", "code"}};
    request->cookies["oauth_" + callbackLogin.state] = callbackLogin.state;
    callback::OAuth2CallbackHandler callback(client);
    callback(request, response);
    claims.purpose = "id";
    claims.nonce = callbackParameters.at("nonce");
    finish = std::move(pending);
    finish({200, Json({{"access_token", access}, {"id_token", signer.sign(claims)}}).dump()});
    require(response->location == "/private" && response->headers.at("Set-Cookie").find("access_token=" + access) == 0 &&
                response->cookies.at("oauth_" + callbackLogin.state).empty(),
            "Callback cookie/redirect failed");
    callback(request, response);
    require(response->code == 401 && !pending, "Callback adapter accepted replay");
    claims.purpose = "access";
    claims.mfaVerified = false;
    client->authorize(signer.sign(claims), [&](bool ok, auto) {
        accepted = ok;
    });
    require(!accepted && !pending, "Password-only token accepted");
    require(client->cookieRequestAllowed("POST", "https://app.example") && !client->cookieRequestAllowed("POST", "https://evil.example") &&
                !client->cookieRequestAllowed("POST", "") && client->cookieRequestAllowed("GET", ""),
            "Cookie origin policy failed");
    for (const auto* bad : {"http://evil.example/token",
                            "https://user@idp.example/token",
                            "https://idp.example:999999999999/token",
                            "https://idp.example/\r\nHeader"}) {
        rejects([&] {
            endpoint(bad);
        });
    }
    require(endpoint("https://idp.example/token").port == 443 && endpoint("http://localhost:8083/token").port == 8083,
            "Endpoint parsing failed");
    const auto cookie = client->cookie("access_token", access, 300);
    require(cookie.find("HttpOnly") != std::string::npos && cookie.find("Secure") != std::string::npos &&
                cookie.find("SameSite=Lax") != std::string::npos,
            "Unsafe credential cookie");
    require(!localPath("//evil") && !localPath("/\\evil") && !localPath("/\r\nX: y"), "Unsafe local redirect");
}

static void idpConfigurationTests() {
    IdpConfig config;
    for (const auto& issuer : {"", "https://idp.example/", "https://idp.example/path"}) {
        config.issuer = issuer;
        rejects(
            [&] {
                IdpMiddleware middleware(config);
            },
            "IDP issuer");
    }
    config.issuer = "http://remote.example";
    rejects(
        [&] {
            IdpMiddleware middleware(config);
        },
        "HTTPS required");
    config.issuer = "http://localhost:8083";
    rejects(
        [&] {
            IdpMiddleware middleware(config);
        },
        "paths are required");
    config.databasePath = ":memory:";
    config.privateKeyPath = "missing-private-key.pem";
    config.totpKeyPath = "missing-totp-key";
    config.clients = Json::array();
    rejects(
        [&] {
            IdpMiddleware middleware(config);
        },
        "JSON object");
    config.clients = {{"app", Json::array({"http://remote.example/callback"})}};
    rejects(
        [&] {
            IdpMiddleware middleware(config);
        },
        "HTTPS required");
    config.clients = Json::object();
    rejects(
        [&] {
            IdpMiddleware middleware(config);
        },
        "Cannot open configured private key");
}

int main() {
    int failed = 0;
    for (const auto& [name, test] : std::vector<std::pair<std::string, std::function<void()>>>{{"store", storeTests},
                                                                                               {"IDP configuration", idpConfigurationTests},
                                                                                               {"tokens/client", tokenAndClientTests},
                                                                                               {"reset/migration", resetAndMigrationTests},
                                                                                               {"google identity", googleTests}}) {
        try {
            test();
            std::cout << name << ": passed\n";
        } catch (const std::exception& error) {
            ++failed;
            std::cerr << name << ": " << error.what() << '\n';
        }
    }
    return failed;
}
