#include "OAuthClient.h"

namespace snodec::auth {
    OAuthClient::OAuthClient(std::string issuer,
                             std::string clientId,
                             std::string callbackUrl,
                             std::string publicKey,
                             HttpExchange exchange,
                             std::string cookieName,
                             unsigned cookieLifetime,
                             std::function<int64_t()> clock)
        : issuer_(std::move(issuer))
        , clientId_(std::move(clientId))
        , callbackUrl_(std::move(callbackUrl))
        , verifier_(issuer_, clientId_, publicKey, clock)
        , exchange_(std::move(exchange))
        , cookieName_(std::move(cookieName))
        , cookieLifetime_(cookieLifetime)
        , sessions_(std::make_shared<std::map<std::string, std::shared_ptr<Session>>>())
        , clock_(std::move(clock)) {
        require(!cookieName_.empty() &&
                    cookieName_.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&'*+-.^_`|~") ==
                        std::string::npos,
                "Invalid access cookie name");
        require(cookieLifetime_ > 0, "Invalid access cookie lifetime");
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
        std::erase_if(transactions_, [now = clock_()](const auto& item) {
            return item.second.expires <= now;
        });
        std::erase_if(*sessions_, [now = clock_()](const auto& item) {
            return item.second->expires <= now;
        });
        require(transactions_.size() < 4096, "Too many pending logins");
        Login login{randomToken(), ""};
        const Transaction transaction{randomToken(), randomToken(), localPath(localReturn) ? localReturn : "/", clock_() + 600};
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
        if (state.empty() || state != browserState || code.empty() || found == transactions_.end() || found->second.expires <= clock_()) {
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
                      [verifier = verifier_, sessions = sessions_, clock = clock_, lifetime = cookieLifetime_, transaction, done](
                          HttpResult response) mutable {
                          std::string credential;
                          try {
                              auto session = std::make_shared<Session>();
                              session->tokens = tokens(verifier, std::move(response), transaction.nonce, clock());
                              session->nonce = transaction.nonce;
                              session->expires = clock() + lifetime;
                              session->nextCheck = session->tokens.renewAt;
                              credential = randomToken();
                              require(sessions->emplace(sha256(credential), session).second, "Session collision");
                          } catch (const std::exception&) {
                              credential.clear();
                          }
                          done(credential, credential.empty() ? "" : transaction.target);
                      });
        }
    }

    OAuthClient::Tokens OAuthClient::tokens(JwtVerifier verifier, HttpResult response, const std::string& nonce, int64_t now) {
        require(response.status == 200, "Token exchange failed");
        const auto data = Json::parse(response.body);
        Tokens result;
        result.access = data.at("access_token").get<std::string>();
        result.refresh = data.at("refresh_token").get<std::string>();
        JwtClaims identity;
        std::string error;
        require(data.at("refresh_retry") == true && !result.refresh.empty() && verifier.verify(result.access, result.claims, error) &&
                    result.claims.mfaVerified && verifier.verify(data.at("id_token").get<std::string>(), identity, error, "id") &&
                    identity.nonce == nonce && identity.subject == result.claims.subject && identity.sessionId == result.claims.sessionId,
                "Invalid token response");
        const auto expiry = std::chrono::duration_cast<std::chrono::seconds>(result.claims.expiresAt.time_since_epoch()).count();
        result.renewAt = now + std::max<int64_t>(1, (expiry - now) * 4 / 5);
        return result;
    }

    void OAuthClient::inspect(JwtVerifier verifier,
                              HttpExchange exchange,
                              const std::string& issuer,
                              const std::string& clientId,
                              const std::string& token,
                              Completion done) {
        JwtClaims claims;
        std::string error;
        if (!verifier.verify(token, claims, error) || !claims.mfaVerified) {
            done(Authorization::Rejected, {});
        } else {
            exchange(issuer + "/oauth2/introspect",
                     "POST",
                     formEncode({{"token", token}, {"client_id", clientId}}),
                     {{"Content-Type", "application/x-www-form-urlencoded"}, {"Authorization", "Bearer " + token}},
                     [claims, done](HttpResult response) {
                         auto status =
                             response.status == 0 || response.status >= 500 ? Authorization::Unavailable : Authorization::Rejected;
                         try {
                             const auto data = Json::parse(response.body);
                             if (response.status == 200 && data.at("active").get<bool>() && data.at("sub") == claims.subject &&
                                 data.at("sid") == claims.sessionId && data.at("mfa_verified") == true) {
                                 status = Authorization::Accepted;
                             }
                         } catch (const std::exception&) {
                         }
                         done(status, status == Authorization::Accepted ? claims : JwtClaims{});
                     });
        }
    }

    void OAuthClient::authorize(const std::string& token, std::function<void(bool, JwtClaims)> done) {
        inspect(verifier_, exchange_, issuer_, clientId_, token, [done](Authorization status, JwtClaims claims) {
            done(status == Authorization::Accepted, std::move(claims));
        });
    }

    bool OAuthClient::renewalDue(const std::string& credential) const {
        const auto found = sessions_->find(sha256(credential));
        return found == sessions_->end() || clock_() >= std::min(found->second->nextCheck, found->second->expires);
    }

    void OAuthClient::authenticate(const std::string& credential, bool bearer, Completion done) {
        if (bearer) {
            authorize(credential, [done](bool accepted, JwtClaims claims) {
                done(accepted ? Authorization::Accepted : Authorization::Rejected, std::move(claims));
            });
        } else {
            authorizeSession(credential, std::move(done));
        }
    }

    void OAuthClient::authorizeSession(const std::string& credential, Completion done) {
        const auto key = sha256(credential);
        const auto found = sessions_->find(key);
        if (found == sessions_->end() || found->second->expires <= clock_()) {
            sessions_->erase(key);
            done(Authorization::Rejected, {});
        } else {
            const auto session = found->second;
            session->waiting.push_back(std::move(done));
            if (session->waiting.size() == 1) {
                const auto finish = [sessions = sessions_, session, key, clock = clock_](Authorization status, JwtClaims claims) {
                    if (clock() >= session->expires) {
                        status = Authorization::Rejected;
                        claims = {};
                    }
                    session->nextCheck = status == Authorization::Unavailable ? clock() + 5 : session->tokens.renewAt;
                    if (status == Authorization::Rejected) {
                        sessions->erase(key);
                    }
                    auto waiting = std::move(session->waiting);
                    session->waiting.clear();
                    for (const auto& callback : waiting) {
                        callback(status, claims);
                    }
                };
                if (clock_() >= session->tokens.renewAt || !session->operation.empty()) {
                    if (session->operation.empty()) {
                        session->operation = randomToken();
                    }
                    exchange_(issuer_ + "/oauth2/token",
                              "POST",
                              formEncode({{"grant_type", "refresh_token"},
                                          {"refresh_token", session->tokens.refresh},
                                          {"client_id", clientId_},
                                          {"refresh_request_id", session->operation}}),
                              {{"Content-Type", "application/x-www-form-urlencoded"}},
                              [verifier = verifier_,
                               exchange = exchange_,
                               issuer = issuer_,
                               clientId = clientId_,
                               clock = clock_,
                               session,
                               finish](HttpResult response) mutable {
                                  if (response.status == 0 || response.status >= 500) {
                                      finish(Authorization::Unavailable, {});
                                  } else {
                                      bool valid = false;
                                      try {
                                          auto renewed = tokens(verifier, std::move(response), session->nonce, clock());
                                          require(renewed.claims.subject == session->tokens.claims.subject &&
                                                      renewed.claims.sessionId == session->tokens.claims.sessionId &&
                                                      renewed.claims.scopes == session->tokens.claims.scopes,
                                                  "Renewal changed identity");
                                          session->tokens = std::move(renewed);
                                          session->operation.clear();
                                          valid = true;
                                      } catch (const std::exception&) {
                                      }
                                      if (valid) {
                                          inspect(verifier, exchange, issuer, clientId, session->tokens.access, finish);
                                      } else {
                                          finish(Authorization::Rejected, {});
                                      }
                                  }
                              });
                } else {
                    inspect(verifier_, exchange_, issuer_, clientId_, session->tokens.access, finish);
                }
            }
        }
    }

    std::string OAuthClient::cookie(const std::string& name, const std::string& value, unsigned seconds) const {
        return name + "=" + value + "; Path=/; HttpOnly; SameSite=Lax; Max-Age=" + std::to_string(seconds) +
               (callbackUrl_.starts_with("https://") ? "; Secure" : "");
    }

    const std::string& OAuthClient::cookieName() const {
        return cookieName_;
    }

    unsigned OAuthClient::cookieLifetime() const {
        return cookieLifetime_;
    }

    bool OAuthClient::cookieRequestAllowed(const std::string& method, const std::string& origin) const {
        return method == "GET" || method == "HEAD" || method == "OPTIONS" || origin == endpoint(callbackUrl_).origin;
    }
} // namespace snodec::auth
