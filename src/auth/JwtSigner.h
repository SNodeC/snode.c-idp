#pragma once

#include "JwtVerifier.h"

#include <string>

namespace snodec {
    namespace auth {

        class JwtSigner {
        public:
            JwtSigner(const std::string& issuer, const std::string& privateKeyPem);

            std::string sign(const JwtClaims& claims);
            std::string jwks() const;
            std::string publicKey() const;

        private:
            std::string issuer_;
            std::string privateKeyPem_;

            std::string keyId_;
            std::string jwks_;
            std::string publicKey_;
        };

    } // namespace auth
} // namespace snodec
