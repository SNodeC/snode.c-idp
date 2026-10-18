#pragma once

#include "Security.h"
#include "UserContext.h"

#include <chrono>
#include <optional>
#include <string>
#include <vector>

namespace snodec {
    namespace auth {

        Json verifiedJwt(const std::string& token, const std::string& publicKey);
        Json googleIdentity(const std::string& token, const Json& jwks, const std::string& audience, const std::string& nonce);

        struct JwtClaims {
            std::string subject;
            std::string username;
            std::string email;
            std::vector<std::string> scopes;
            std::chrono::system_clock::time_point expiresAt;
            std::string issuer;
            std::string audience;
            bool mfaVerified = false;
            std::string sessionId;
            std::string nonce;
            std::string purpose = "access";
        };

        class JwtVerifier {
        public:
            JwtVerifier(const std::string& issuer, const std::string& audience, const std::string& publicKeyPem);

            bool verify(const std::string& token, JwtClaims& outClaims, std::string& error, const std::string& purpose = "access");

        private:
            std::string issuer_;
            std::string audience_;
            std::string publicKeyPem_;
        };

    } // namespace auth
} // namespace snodec
