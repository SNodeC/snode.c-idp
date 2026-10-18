#include "HttpExchange.h"

#include "web/http/ConfigHttpParser.h"
#include "web/http/client/Response.h"
#include "web/http/legacy/in/Client.h"
#include "web/http/tls/in/Client.h"

#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <regex>

namespace snodec::auth {
    template <typename Client>
    static void exchange(const std::string& host,
                         uint16_t port,
                         const std::string& target,
                         const std::string& method,
                         const std::string& body,
                         const std::map<std::string, std::string>& headers,
                         HttpCompletion done) {
        auto completion = std::make_shared<HttpCompletion>(std::move(done));
        auto finish = [completion](HttpResult result) {
            if (*completion) {
                auto callback = std::move(*completion);
                callback(std::move(result));
            }
        };
        try {
            Client client(
                {},
                {},
                [finish](const auto&) {
                    finish({});
                },
                [=](const auto& request) {
                    request->method = method;
                    request->url = target;
                    request->host(host + ":" + std::to_string(port));
                    request->set(headers).set("Connection", "close");
                    request->send(
                        body,
                        [finish](const auto&, const auto& response) {
                            HttpResult result;
                            if (response->body.size() <= 1048576) {
                                result.status = std::stoi(response->statusCode);
                                result.body.assign(response->body.begin(), response->body.end());
                            }
                            finish(std::move(result));
                        },
                        [finish](const auto&, const auto&) {
                            finish({});
                        });
                },
                [](const auto&) {
                });
            client.getConfig()->setConnectTimeout({10, 0});
            client.getConfig()->setReadTimeout({10, 0});
            client.getConfig()->setWriteTimeout({10, 0});
            client.getConfig()->setReconnect(false);
            client.getConfig()->setRetry(false);
            client.getConfig()
                ->net::config::ConfigInstance::template getSubCommand<web::http::client::ConfigHTTP>()
                ->getParserConfig()
                ->setMaximumBodyBytes(1048576);
            client.getConfig()
                ->net::config::ConfigInstance::template getSubCommand<web::http::client::ConfigHTTP>()
                ->getParserConfig()
                ->setMaximumHeaderBytes(32768);
            if constexpr (std::is_same_v<Client, web::http::tls::in::Client>) {
                client.getConfig()->setSni(host);
                client.getConfig()->setCaCertDirUseDefault(true);
                client.getConfig()->setCaCertAcceptUnknown(false);
                SSL_CTX* ctx = client.getConfig()->getSslCtx();
                require(ctx != nullptr, "Cannot initialize TLS");
                SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
                require(SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) == 1, "Cannot configure TLS");
                in_addr address{};
                auto* params = SSL_CTX_get0_param(ctx);
                const int configured = inet_pton(AF_INET, host.c_str(), &address) == 1
                                           ? X509_VERIFY_PARAM_set1_ip_asc(params, host.c_str())
                                           : X509_VERIFY_PARAM_set1_host(params, host.c_str(), 0);
                require(configured == 1, "Cannot configure TLS hostname verification");
            }
            client.connect(typename Client::SocketAddress(host, port), [finish](const auto&, core::socket::State state) {
                if (state != core::socket::State::OK) {
                    finish({});
                }
            });
        } catch (const std::exception&) {
            finish({});
        }
    }

    void httpExchange(const std::string& url,
                      const std::string& method,
                      const std::string& body,
                      const std::map<std::string, std::string>& headers,
                      HttpCompletion done) {
        try {
            const auto destination = endpoint(url);
            if (destination.tls) {
                exchange<web::http::tls::in::Client>(
                    destination.host, destination.port, destination.target, method, body, headers, std::move(done));
            } else {
                exchange<web::http::legacy::in::Client>(
                    destination.host, destination.port, destination.target, method, body, headers, std::move(done));
            }
        } catch (const std::exception&) {
            if (done) {
                done({});
            }
        }
    }
} // namespace snodec::auth
