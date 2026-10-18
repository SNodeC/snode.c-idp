#pragma once

#include <chrono>
#include <string>
#include <vector>

namespace snodec {
    namespace auth {

        struct UserContext {
            std::string id;
            std::string username;
            std::vector<std::string> scopes;
            std::string email;
            bool mfaVerified = false;

            bool hasScope(const std::string& scope) const;
        };

    } // namespace auth
} // namespace snodec
