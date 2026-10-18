#pragma once
#include "HttpExchange.h"
#include "JwtVerifier.h"

#include <map>
#include <memory>

namespace snodec::auth {
    class OAuthClient {
    public:
        OAuthClient(
            std::string issuer, std::string clientId, std::string callbackUrl, std::string publicKey, HttpExchange exchange = httpExchange);
        struct Login {
            std::string state;
            std::string authorizeUrl;
        };
        std::string accountUrl(const std::string& localReturn) const;
        Login begin(const std::string& localReturn);
        void complete(const std::string& state,
                      const std::string& browserState,
                      const std::string& code,
                      std::function<void(std::string, std::string)> done);
        void authorize(const std::string& token, std::function<void(bool, JwtClaims)> done);
        std::string cookie(const std::string& name, const std::string& value, unsigned seconds) const;
        bool cookieRequestAllowed(const std::string& method, const std::string& origin) const;

    private:
        struct Transaction {
            std::string verifier, nonce, target;
            int64_t expires;
        };
        std::string issuer_, clientId_, callbackUrl_;
        JwtVerifier verifier_;
        HttpExchange exchange_;
        std::map<std::string, Transaction> transactions_;
    };
} // namespace snodec::auth
