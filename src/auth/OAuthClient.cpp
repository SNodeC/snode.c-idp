#include "OAuthClient.h"

namespace snodec::auth {
    OAuthClient::OAuthClient(
        std::string issuer, std::string clientId, std::string callbackUrl, std::string publicKey, HttpExchange exchange)
        : issuer_(std::move(issuer))
        , clientId_(std::move(clientId))
        , callbackUrl_(std::move(callbackUrl))
        , verifier_(issuer_, clientId_, publicKey)
        , exchange_(std::move(exchange)) {
        require(!issuer_.empty() && !clientId_.empty() && !callbackUrl_.empty(), "Missing OAuth configuration");
        endpoint(callbackUrl_);
        require(endpoint(issuer_).origin == issuer_, "Issuer must be an origin without trailing slash");
    }

    std::string OAuthClient::accountUrl(const std::string& localReturn) const {
        require(localPath(localReturn), "Account return must be a local application path");
        const auto target = endpoint(callbackUrl_).origin + localReturn;
        endpoint(target);
        return issuer_ + "/settings?" + formEncode({{"client_id", clientId_}, {"return", target}});
    }

    OAuthClient::Login OAuthClient::begin(const std::string& localReturn) {
        std::erase_if(transactions_, [](const auto& item) {
            return item.second.expires <= epochSeconds();
        });
        require(transactions_.size() < 4096, "Too many pending logins");
        Login login{randomToken(), ""};
        const Transaction transaction{randomToken(), randomToken(), localPath(localReturn) ? localReturn : "/", epochSeconds() + 600};
        transactions_.emplace(login.state, transaction);
        login.authorizeUrl = issuer_ + "/oauth2/authorize?" +
                             formEncode({{"response_type", "code"},
                                         {"client_id", clientId_},
                                         {"redirect_uri", callbackUrl_},
                                         {"app_return", endpoint(callbackUrl_).origin + transaction.target},
                                         {"scope", "openid profile email"},
                                         {"acr_values", "urn:snodec:acr:mfa"},
                                         {"state", login.state},
                                         {"nonce", transaction.nonce},
                                         {"code_challenge", sha256(transaction.verifier)},
                                         {"code_challenge_method", "S256"}});
        return login;
    }

    void OAuthClient::complete(const std::string& state,
                               const std::string& browserState,
                               const std::string& code,
                               std::function<void(std::string, std::string)> done) {
        const auto found = transactions_.find(state);
        if (state.empty() || state != browserState || code.empty() || found == transactions_.end() ||
            found->second.expires <= epochSeconds()) {
            done("", "");
        } else {
            const Transaction transaction = found->second;
            transactions_.erase(found);
            exchange_(issuer_ + "/oauth2/token",
                      "POST",
                      formEncode({{"grant_type", "authorization_code"},
                                  {"code", code},
                                  {"client_id", clientId_},
                                  {"redirect_uri", callbackUrl_},
                                  {"code_verifier", transaction.verifier}}),
                      {{"Content-Type", "application/x-www-form-urlencoded"}},
                      [verifier = verifier_, transaction, done](HttpResult response) mutable {
                          std::string token;
                          try {
                              require(response.status == 200, "Token exchange failed");
                              const auto data = Json::parse(response.body);
                              JwtClaims access, identity;
                              std::string error;
                              const auto candidate = data.at("access_token").get<std::string>();
                              require(verifier.verify(candidate, access, error) && access.mfaVerified &&
                                          verifier.verify(data.at("id_token").get<std::string>(), identity, error, "id") &&
                                          identity.nonce == transaction.nonce && identity.subject == access.subject &&
                                          identity.sessionId == access.sessionId,
                                      "Invalid token response");
                              token = candidate;
                          } catch (const std::exception&) {
                              token.clear();
                          }
                          done(token, token.empty() ? "" : transaction.target);
                      });
        }
    }

    void OAuthClient::authorize(const std::string& token, std::function<void(bool, JwtClaims)> done) {
        JwtClaims claims;
        std::string error;
        if (!verifier_.verify(token, claims, error) || !claims.mfaVerified) {
            done(false, {});
        } else {
            exchange_(issuer_ + "/oauth2/introspect",
                      "POST",
                      formEncode({{"token", token}, {"client_id", clientId_}}),
                      {{"Content-Type", "application/x-www-form-urlencoded"}, {"Authorization", "Bearer " + token}},
                      [claims, done](HttpResult response) {
                          bool active = false;
                          try {
                              const auto data = Json::parse(response.body);
                              active = response.status == 200 && data.at("active").get<bool>() && data.at("sub") == claims.subject &&
                                       data.at("sid") == claims.sessionId && data.at("mfa_verified") == true;
                          } catch (const std::exception&) {
                              active = false;
                          }
                          done(active, active ? claims : JwtClaims{});
                      });
        }
    }

    std::string OAuthClient::cookie(const std::string& name, const std::string& value, unsigned seconds) const {
        return name + "=" + value + "; Path=/; HttpOnly; SameSite=Lax; Max-Age=" + std::to_string(seconds) +
               (callbackUrl_.starts_with("https://") ? "; Secure" : "");
    }

    bool OAuthClient::cookieRequestAllowed(const std::string& method, const std::string& origin) const {
        return method == "GET" || method == "HEAD" || method == "OPTIONS" || origin == endpoint(callbackUrl_).origin;
    }
} // namespace snodec::auth
