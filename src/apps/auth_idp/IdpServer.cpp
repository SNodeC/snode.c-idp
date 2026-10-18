/* SNode.C IDP standalone host. Authentication is owned by IdpMiddleware. */
#include "Log.h"
#include "auth/IdpMiddleware.h"
#include "auth/Security.h"
#include "core/SNodeC.h"
#include "express/legacy/in/WebApp.h"
#include "express/middleware/VHost.h"
#include "web/http/CiStringMap.h"

#include <cstdint>
#include <cstdlib>
#include <regex>
#include <set>
#include <stdexcept>
#include <utility>

int main(int argc, char* argv[]) {
    core::SNodeC::init(argc, argv);
    const auto env = [](const char* key, const std::string& fallback) {
        const char* value = std::getenv(key);
        return value ? std::string(value) : fallback;
    };
    snodec::auth::IdpConfig config;
    config.issuer = env("IDP_ISSUER", env("IDP_BASE_URL", "http://localhost:8083"));
    if (config.issuer != env("IDP_BASE_URL", "http://localhost:8083")) {
        throw std::invalid_argument("IDP_ISSUER and IDP_BASE_URL must match");
    }
    config.clients = nlohmann::json::parse(env("IDP_CLIENTS", "{}"));
    config.databasePath = env("DB_PATH", "snodec_auth.db");
    config.privateKeyPath = env("IDP_PRIVATE_KEY_PATH", "src/apps/auth_idp/keys/private_key.pem");
    config.totpKeyPath = env("TOTP_KEY_PATH", "");
    config.protectedAppUrl = env("PROTECTED_WEBAPP_URL", "");
    config.smtpCommand = env("SMTP_COMMAND", "");
    config.googleClientId = env("OAUTH_GOOGLE_CLIENT_ID", "");
    config.googleClientSecret = env("OAUTH_GOOGLE_CLIENT_SECRET", "");
    const int port = std::stoi(env("IDP_PORT", "8083"));
    if (port < 0 || port > 65535) {
        throw std::out_of_range("IDP_PORT must be between 0 and 65535");
    }
    const auto idpHost = snodec::auth::endpoint(config.issuer).host;
    const std::regex hostname(R"(^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$)");
    snodec::auth::require(idpHost.size() <= 253 && std::regex_match(idpHost, hostname), "Invalid IDP hostname");
    std::set<std::string, web::http::ciLess> redirectHosts;
    const auto redirectJson = env("HOST_REDIRECTS", "");
    const auto redirects = nlohmann::json::parse(redirectJson.empty() ? "{}" : redirectJson,
                                                 [&redirectHosts](int depth, nlohmann::json::parse_event_t event, nlohmann::json& value) {
                                                     if (depth == 1 && event == nlohmann::json::parse_event_t::key) {
                                                         snodec::auth::require(redirectHosts.insert(value.get<std::string>()).second,
                                                                               "Duplicate redirect hostname");
                                                     }
                                                     return true;
                                                 });
    snodec::auth::require(redirects.is_object(), "HOST_REDIRECTS must be a JSON object");
    for (const auto& [host, destination] : redirects.items()) {
        snodec::auth::require(host.size() <= 253 && std::regex_match(host, hostname) && !web::http::ciEquals(host, idpHost),
                              "Invalid redirect hostname or conflict with IDP hostname");
        snodec::auth::require(destination.is_string(), "Redirect destination must be a URL string");
        snodec::auth::endpoint(destination.get<std::string>());
    }
    const express::legacy::in::WebApp app("IdpServer");
    const auto& idp = express::middleware::VHost(idpHost);
    idp.use(snodec::auth::IdpMiddleware(std::move(config)));
    app.use(idp);
    app.use([redirects] APPLICATION(req, res) {
        auto host = req->get("Host");
        if (const auto port = host.find(':'); port != std::string::npos && port == host.rfind(':')) {
            host.erase(port);
        }
        if (const auto destination = redirects.find(host); destination != redirects.end()) {
            res->set("Cache-Control", "no-store").set("Referrer-Policy", "no-referrer").redirect(303, destination->get<std::string>());
        } else {
            res->status(404).send("Not found");
        }
    });
    app.listen(static_cast<uint16_t>(port), [port](const express::legacy::in::WebApp::SocketAddress& addr, const core::socket::State& st) {
        if (st == core::socket::State::OK) {
            snode::log::application().info() << "IdP Server listening on port " << port;
        } else {
            snode::log::application().error() << "IdP Server failed to start: " << addr.toString();
        }
    });

    return core::SNodeC::start();
}
