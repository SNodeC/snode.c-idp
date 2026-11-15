#pragma once
#include "HttpExchange.h"
#include "JwtVerifier.h"

#include <map>
#include <memory>

namespace snodec::auth {
    class OAuthClient {
    public:
        OAuthClient(std::string issuer,
                    std::string clientId,
                    std::string callbackUrl,
                    std::string publicKey,
                    HttpExchange exchange = httpExchange,
                    std::string cookieName = "access_token",
                    unsigned cookieLifetime = 300,
                    std::function<int64_t()> clock = epochSeconds);
        enum class Authorization { Accepted, Rejected, Unavailable };
        using Completion = std::function<void(Authorization, JwtClaims)>;
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
        void authorizeSession(const std::string& credential, Completion done);
        void authenticate(const std::string& credential, bool bearer, Completion done);
        bool renewalDue(const std::string& credential) const;
        std::string cookie(const std::string& name, const std::string& value, unsigned seconds) const;
        const std::string& cookieName() const;
        unsigned cookieLifetime() const;
        bool cookieRequestAllowed(const std::string& method, const std::string& origin) const;

    private:
        struct Transaction {
            std::string verifier, nonce, target;
            int64_t expires;
        };
        struct Tokens {
            std::string access, refresh;
            JwtClaims claims;
            int64_t renewAt = 0;
        };
        struct Session {
            Tokens tokens;
            std::string nonce, operation;
            int64_t expires = 0, nextCheck = 0;
            std::vector<Completion> waiting;
        };
        static Tokens tokens(JwtVerifier verifier, HttpResult response, const std::string& nonce, int64_t now);
        static void inspect(JwtVerifier verifier,
                            HttpExchange exchange,
                            const std::string& issuer,
                            const std::string& clientId,
                            const std::string& token,
                            Completion done);
        std::string issuer_, clientId_, callbackUrl_;
        JwtVerifier verifier_;
        HttpExchange exchange_;
        std::string cookieName_;
        unsigned cookieLifetime_;
        std::map<std::string, Transaction> transactions_;
        std::shared_ptr<std::map<std::string, std::shared_ptr<Session>>> sessions_;
        std::function<int64_t()> clock_;
    };
} // namespace snodec::auth
