#include "auth/AuthMiddleware.h"
#include "auth/JwtAuthMiddleware.h"
#include "auth/OAuth2CallbackHandler.h"
#include "core/SNodeC.h"
#include "express/legacy/in/WebApp.h"

#include <cstdlib>

int main(int argc, char** argv) {
    core::SNodeC::init(argc, argv);
    const express::legacy::in::WebApp app("LiveClient");
    auto client = std::make_shared<snodec::auth::OAuthClient>(std::getenv("TEST_ISSUER"),
                                                              std::getenv("TEST_CLIENT"),
                                                              std::getenv("TEST_CALLBACK"),
                                                              snodec::auth::middleware::loadPublicKey(std::getenv("TEST_PUBLIC_KEY")));
    snodec::auth::middleware::JwtAuthMiddleware browser(client);
    snodec::auth::callback::OAuth2CallbackHandler callback(client);
    snodec::auth::AuthMiddleware api(client);
    app.get("/auth/callback", callback);
    app.use("/private", browser);
    app.get("/private", [] APPLICATION(req, res) {
        res->send("MFA authorized");
    });
    app.use("/api", api.handler());
    app.get("/api", [] APPLICATION(req, res) {
        res->send("API authorized");
    });
    app.listen(static_cast<uint16_t>(std::stoi(std::getenv("TEST_PORT"))), [](const auto&, const auto&) {
    });
    return core::SNodeC::start();
}
