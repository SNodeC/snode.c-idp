#include "auth/IdpMiddleware.h"
#include "core/SNodeC.h"
#include "express/legacy/in/WebApp.h"
#include "express/middleware/VHost.h"

#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <utility>
#include <vector>

static express::Router configuredRouter(const nlohmann::json& values) {
    snodec::auth::IdpConfig config;
    config.issuer = values.at("issuer");
    config.clients = values.at("clients");
    config.databasePath = values.at("databasePath");
    config.privateKeyPath = values.at("privateKeyPath");
    config.totpKeyPath = values.at("totpKeyPath");
    config.protectedAppUrl = values.at("protectedAppUrl");
    config.smtpCommand = values.at("smtpCommand");
    return snodec::auth::IdpMiddleware(std::move(config));
}

int main(int argc, char** argv) {
    core::SNodeC::init(argc, argv);
    std::ifstream file(std::getenv("TEST_IDP_CONFIG"));
    const auto configurations = nlohmann::json::parse(file);
    std::vector<express::legacy::in::WebApp> applications;
    for (const auto& values : configurations) {
        applications.emplace_back(values.at("name").get<std::string>());
        // The configuration, derived middleware and temporary Router are gone
        // before the first request: mounted handlers must retain their own state.
        const auto hostname = "localhost:" + std::to_string(values.at("port").get<uint16_t>());
        const auto& host = express::middleware::VHost(hostname);
        host.use(configuredRouter(values));
        applications.back().use(host);
        applications.back().use([] APPLICATION(req, res) {
            res->status(req->path == "/unclaimed" ? 404 : 200).send("downstream router");
        });
        applications.back().listen(values.at("port").get<uint16_t>(), [](const auto&, const auto&) {
        });
    }
    return core::SNodeC::start();
}
