#include "AuthMiddleware.h"

#include "express/legacy/in/WebApp.h" // For MIDDLEWARE macro and other express types

#include <iostream>

namespace snodec {
    namespace auth {

        AuthMiddleware::AuthMiddleware(std::shared_ptr<OAuthClient> client)
            : client_(std::move(client)) {
        }

        std::function<void(const std::shared_ptr<express::Request>&, const std::shared_ptr<express::Response>&, express::Next&)>
        AuthMiddleware::handler() {
            return [client = client_] MIDDLEWARE(req, res, next) {
                const auto header = req->get("Authorization");
                const auto token = header.starts_with("Bearer ") ? header.substr(7) : req->cookie("access_token");
                if (!header.starts_with("Bearer ") && !client->cookieRequestAllowed(req->method, req->get("Origin"))) {
                    res->status(403).send("Untrusted request origin");
                } else {
                    client->authorize(token, [req, res, next](bool accepted, JwtClaims claims) mutable {
                        if (accepted) {
                            req->setAttribute<UserContext>(
                                {claims.subject, claims.username, claims.scopes, claims.email, claims.mfaVerified});
                            next();
                        } else {
                            res->status(401).send("Unauthorized");
                        }
                    });
                }
            };
        }

        const UserContext* AuthMiddleware::getUser(const std::shared_ptr<express::Request>& req) {
            const UserContext* user = nullptr;
            req->getAttribute<UserContext>([&user](UserContext& ctx) {
                user = &ctx;
            });
            return user;
        }

    } // namespace auth
} // namespace snodec
