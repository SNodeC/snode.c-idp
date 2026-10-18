/*
 * SNode.C - A Slim Toolkit for Network Communication
 * Copyright (C) Volker Christian <me@vchrist.at>
 *               2020, 2021, 2022, 2023, 2024, 2025
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * MIT License
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#pragma once
#include "OAuthClient.h"
#include "UserContext.h"

#include <fstream>
#include <sstream>

namespace snodec::auth::middleware {
    class JwtAuthMiddleware {
    public:
        explicit JwtAuthMiddleware(std::shared_ptr<OAuthClient> client)
            : client_(std::move(client)) {
        }
        template <typename Request, typename Response, typename Next>
        void operator()(Request req, Response res, Next next) {
            const std::string header = req->get("Authorization");
            const auto token = header.starts_with("Bearer ") ? header.substr(7) : req->cookie("access_token");
            if (!header.starts_with("Bearer ") && !client_->cookieRequestAllowed(req->method, req->get("Origin"))) {
                res->status(403).send("Untrusted request origin");
            } else {
                client_->authorize(token, [client = client_, req, res, next, header](bool accepted, JwtClaims claims) mutable {
                    if (accepted) {
                        req->template setAttribute<UserContext>(
                            {claims.subject, claims.username, claims.scopes, claims.email, claims.mfaVerified});
                        req->template setAttribute<std::string>(claims.subject, "X-User-Id");
                        req->template setAttribute<std::string>(claims.username, "X-Username");
                        req->template setAttribute<std::string>(claims.email, "X-Email");
                        req->template setAttribute<bool>(claims.mfaVerified, "X-MfaVerified");
                        next();
                    } else if (!header.empty() || (req->method != "GET" && req->method != "HEAD")) {
                        res->set("Set-Cookie", client->cookie("access_token", "", 0));
                        res->status(401).send("Unauthorized");
                    } else {
                        try {
                            const auto login = client->begin(req->originalUrl);
                            res->set("Set-Cookie", client->cookie("oauth_" + login.state, login.state, 600));
                            res->cookie("access_token", "", {{"Path", "/"}, {"Max-Age", "0"}}).redirect(login.authorizeUrl);
                        } catch (const std::exception&) {
                            res->status(503).send("Authentication unavailable");
                        }
                    }
                });
            }
        }

    private:
        std::shared_ptr<OAuthClient> client_;
    };
    inline std::string loadPublicKey(const std::string& filename) {
        std::ifstream file(filename);
        require(file.good(), "Cannot read verification key");
        std::ostringstream content;
        content << file.rdbuf();
        return content.str();
    }
} // namespace snodec::auth::middleware
