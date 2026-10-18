#pragma once
#include "Security.h"

#include <functional>
#include <map>

namespace snodec::auth {
    struct HttpResult {
        int status = 0;
        std::string body;
    };
    using HttpCompletion = std::function<void(HttpResult)>;
    using HttpExchange = std::function<void(
        const std::string&, const std::string&, const std::string&, const std::map<std::string, std::string>&, HttpCompletion)>;
    void httpExchange(const std::string& url,
                      const std::string& method,
                      const std::string& body,
                      const std::map<std::string, std::string>& headers,
                      HttpCompletion done);
} // namespace snodec::auth
