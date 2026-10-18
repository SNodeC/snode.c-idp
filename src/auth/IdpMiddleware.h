#pragma once

#include "express/Router.h"

#include <nlohmann/json.hpp>
#include <string>

namespace snodec::auth {
    struct IdpConfig {
        std::string issuer;
        nlohmann::json clients;
        std::string databasePath;
        std::string privateKeyPath;
        std::string totpKeyPath;
        std::string protectedAppUrl;
        std::string smtpCommand;
        std::string googleClientId;
        std::string googleClientSecret;
    };

    // Mount at the origin root. Copies share the same routes and owned state.
    // Construction validates configuration and initializes storage; it starts no listener.
    class IdpMiddleware : public express::Router {
    public:
        explicit IdpMiddleware(IdpConfig config);
    };
} // namespace snodec::auth
