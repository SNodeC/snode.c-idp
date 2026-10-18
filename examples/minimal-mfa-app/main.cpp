#include "auth/JwtAuthMiddleware.h"
#include "auth/OAuth2CallbackHandler.h"
#include "core/SNodeC.h"
#include "express/legacy/in/WebApp.h"
#include "express/middleware/StaticMiddleware.h"
#include "express/tls/in/WebApp.h"

#include <cstdlib>
#include <memory>

int main(int argc, char** argv) {
    core::SNodeC::init(argc, argv);
    const auto env = [](const char* name, const std::string& fallback) {
        const char* value = std::getenv(name);
        return value ? std::string(value) : fallback;
    };
    const auto issuer = env("IDP_BASE_URL", "http://localhost:8083");
    const auto callbackUrl = env("APP_CALLBACK_URL", "http://localhost:8084/auth/callback");
    const auto callbackEndpoint = snodec::auth::endpoint(callbackUrl);
    const auto callbackPath = callbackEndpoint.target;
    snodec::auth::require(callbackPath == "/auth/callback", "Example callback path must be /auth/callback");
    const auto port = std::stoi(env("APP_PORT", std::to_string(callbackEndpoint.port)));
    snodec::auth::require(port > 0 && port <= 65535 && (!callbackEndpoint.tls || port == callbackEndpoint.port),
                          "Application TLS port must match callback URL");
    auto client =
        std::make_shared<snodec::auth::OAuthClient>(issuer,
                                                    env("APP_CLIENT_ID", "minimal-mfa-app"),
                                                    callbackUrl,
                                                    snodec::auth::middleware::loadPublicKey(env("IDP_PUBLIC_KEY_PATH", "idp-public.pem")));
    snodec::auth::middleware::JwtAuthMiddleware auth(client);
    snodec::auth::callback::OAuth2CallbackHandler callback(client);
    const express::Router app;
    app.get(callbackPath, callback);
    app.get("/account", [issuer] APPLICATION(req, res) {
        res->redirect(303, issuer + "/settings");
    });
    app.get("/sign-out", [issuer] APPLICATION(req, res) {
        res->redirect(303, issuer + "/auth/logout");
    });
    app.use("/private", auth);
    app.use("/private", express::middleware::StaticMiddleware("pages/private"));
    app.use(express::middleware::StaticMiddleware("public"));
    const auto serve = [port](const auto& server) {
        server.listen(static_cast<uint16_t>(port), [](const auto&, const auto&) {
        });
        return core::SNodeC::start();
    };
    int result;
    if (callbackEndpoint.tls) {
        result = serve(express::tls::in::WebApp("MinimalMfaApp", app));
    } else {
        result = serve(express::legacy::in::WebApp("MinimalMfaApp", app));
    }
    return result;
}
