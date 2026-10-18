#pragma once

#include "HttpEncode.h"

#include <algorithm>
#include <charconv>
#include <chrono>
#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <regex>
#include <stdexcept>
#include <string>
#include <vector>

namespace snodec::auth {
    using Json = nlohmann::json;

    inline void require(bool condition, const std::string& message) {
        if (!condition) {
            throw std::runtime_error(message);
        }
    }

    inline int64_t epochSeconds() {
        return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    }

    inline std::string base64Url(const std::string& bytes) {
        require(bytes.size() <= 1048576, "Encoding input too large");
        std::string result(4 * ((bytes.size() + 2) / 3), '\0');
        if (!bytes.empty()) {
            EVP_EncodeBlock(reinterpret_cast<unsigned char*>(result.data()),
                            reinterpret_cast<const unsigned char*>(bytes.data()),
                            static_cast<int>(bytes.size()));
        }
        std::replace(result.begin(), result.end(), '+', '-');
        std::replace(result.begin(), result.end(), '/', '_');
        result.erase(std::remove(result.begin(), result.end(), '='), result.end());
        return result;
    }

    inline std::string decodeBase64Url(const std::string& text) {
        require(!text.empty() && text.size() <= 1048576 && text.size() % 4 != 1 &&
                    text.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_") == std::string::npos,
                "Invalid base64url");
        std::string input = text;
        std::replace(input.begin(), input.end(), '-', '+');
        std::replace(input.begin(), input.end(), '_', '/');
        input.append((4 - input.size() % 4) % 4, '=');
        std::string result(input.size() / 4 * 3, '\0');
        const int count = EVP_DecodeBlock(reinterpret_cast<unsigned char*>(result.data()),
                                          reinterpret_cast<const unsigned char*>(input.data()),
                                          static_cast<int>(input.size()));
        require(count >= 0, "Invalid base64url");
        result.resize(static_cast<size_t>(count) - (input.size() - text.size()));
        require(base64Url(result) == text, "Noncanonical base64url");
        return result;
    }

    inline std::string randomToken() {
        std::string bytes(32, '\0');
        require(RAND_bytes_ex(nullptr, reinterpret_cast<unsigned char*>(bytes.data()), bytes.size(), 0) == 1, "Random generator failed");
        return base64Url(bytes);
    }

    inline std::string sha256(const std::string& text) {
        unsigned char digest[SHA256_DIGEST_LENGTH];
        require(SHA256(reinterpret_cast<const unsigned char*>(text.data()), text.size(), digest) != nullptr, "SHA256 failed");
        return base64Url(std::string(reinterpret_cast<const char*>(digest), sizeof(digest)));
    }

    struct Endpoint {
        bool tls;
        std::string host, target, origin;
        uint16_t port;
    };

    inline Endpoint endpoint(const std::string& url) {
        std::smatch match;
        const std::regex pattern(R"(^(https?)://([A-Za-z0-9.-]+)(?::([0-9]+))?(/[^\x00-\x20\x7f#\\]*)?$)");
        require(std::regex_match(url, match, pattern), "Invalid HTTP endpoint");
        const bool tls = match[1] == "https";
        unsigned port = tls ? 443 : 80;
        if (match[3].matched) {
            const auto value = match[3].str();
            const auto parsed = std::from_chars(value.data(), value.data() + value.size(), port);
            require(parsed.ec == std::errc() && parsed.ptr == value.data() + value.size(), "Invalid endpoint port");
        }
        require(port > 0 && port <= 65535 && (tls || match[2] == "127.0.0.1" || match[2] == "localhost"),
                "HTTPS required outside loopback");
        return {tls,
                match[2],
                match[4].matched ? match[4].str() : "/",
                url.substr(0, url.find('/', url.find("://") + 3)),
                static_cast<uint16_t>(port)};
    }

    inline bool localPath(const std::string& path) {
        return !path.empty() && path.front() == '/' && (path.size() == 1 || path[1] != '/') &&
               std::none_of(path.begin(), path.end(), [](unsigned char c) {
                   return c <= 32 || c == 127 || c == '\\';
               });
    }

    inline std::string formEncode(const Json& fields) {
        std::string result;
        for (const auto& [name, value] : fields.items()) {
            require(value.is_string(), "Form value must be a string");
            result += (result.empty() ? "" : "&") + urlEncode(name) + "=" + urlEncode(value.get<std::string>());
        }
        return result;
    }
} // namespace snodec::auth
