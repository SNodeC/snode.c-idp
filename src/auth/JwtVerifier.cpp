#include "JwtVerifier.h"

#include "Security.h"

#include <memory>
#include <openssl/param_build.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

namespace snodec::auth {
    Json verifiedJwt(const std::string& token, const std::string& publicKey) {
        require(token.size() <= 16384, "Token too large");
        const auto first = token.find('.');
        const auto second = token.find('.', first == std::string::npos ? 0 : first + 1);
        require(first != std::string::npos && second != std::string::npos && token.find('.', second + 1) == std::string::npos,
                "Invalid token structure");
        const auto header = Json::parse(decodeBase64Url(token.substr(0, first)));
        require(header.at("alg") == "RS256" && !header.contains("crit"), "Invalid token header");
        const std::string signature = decodeBase64Url(token.substr(second + 1));
        std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new_mem_buf(publicKey.data(), static_cast<int>(publicKey.size())), BIO_free);
        require(bio != nullptr, "Invalid verification key");
        std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr), EVP_PKEY_free);
        std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
        require(key && ctx && EVP_PKEY_is_a(key.get(), "RSA") == 1 &&
                    EVP_DigestVerifyInit(ctx.get(), nullptr, EVP_sha256(), nullptr, key.get()) == 1,
                "Invalid verification key");
        require(EVP_DigestVerify(ctx.get(),
                                 reinterpret_cast<const unsigned char*>(signature.data()),
                                 signature.size(),
                                 reinterpret_cast<const unsigned char*>(token.data()),
                                 second) == 1,
                "Invalid signature");
        return Json::parse(decodeBase64Url(token.substr(first + 1, second - first - 1)));
    }

    Json googleIdentity(const std::string& token, const Json& jwks, const std::string& audience, const std::string& nonce) {
        const auto header = Json::parse(decodeBase64Url(token.substr(0, token.find('.'))));
        const auto kid = header.at("kid").get<std::string>();
        std::string pem;
        for (const auto& jwk : jwks.at("keys")) {
            if (jwk.value("kid", std::string()) == kid && jwk.at("kty") == "RSA" && jwk.at("alg") == "RS256") {
                const auto n = decodeBase64Url(jwk.at("n")), e = decodeBase64Url(jwk.at("e"));
                std::unique_ptr<BIGNUM, decltype(&BN_free)> modulus(
                    BN_bin2bn(reinterpret_cast<const unsigned char*>(n.data()), static_cast<int>(n.size()), nullptr), BN_free);
                std::unique_ptr<BIGNUM, decltype(&BN_free)> exponent(
                    BN_bin2bn(reinterpret_cast<const unsigned char*>(e.data()), static_cast<int>(e.size()), nullptr), BN_free);
                std::unique_ptr<OSSL_PARAM_BLD, decltype(&OSSL_PARAM_BLD_free)> builder(OSSL_PARAM_BLD_new(), OSSL_PARAM_BLD_free);
                require(modulus && exponent && builder && OSSL_PARAM_BLD_push_BN(builder.get(), "n", modulus.get()) == 1 &&
                            OSSL_PARAM_BLD_push_BN(builder.get(), "e", exponent.get()) == 1,
                        "Invalid provider key");
                std::unique_ptr<OSSL_PARAM, decltype(&OSSL_PARAM_free)> params(OSSL_PARAM_BLD_to_param(builder.get()), OSSL_PARAM_free);
                std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr),
                                                                                EVP_PKEY_CTX_free);
                EVP_PKEY* raw = nullptr;
                require(params && ctx && EVP_PKEY_fromdata_init(ctx.get()) == 1 &&
                            EVP_PKEY_fromdata(ctx.get(), &raw, EVP_PKEY_PUBLIC_KEY, params.get()) == 1,
                        "Invalid provider key");
                std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(raw, EVP_PKEY_free);
                std::unique_ptr<BIO, decltype(&BIO_free)> output(BIO_new(BIO_s_mem()), BIO_free);
                require(output && PEM_write_bio_PUBKEY(output.get(), key.get()) == 1, "Invalid provider key");
                char* data = nullptr;
                const auto length = BIO_get_mem_data(output.get(), &data);
                pem.assign(data, static_cast<size_t>(length));
            }
        }
        require(!pem.empty(), "Unknown provider key");
        const auto claims = verifiedJwt(token, pem);
        require((claims.at("iss") == "https://accounts.google.com" || claims.at("iss") == "accounts.google.com") &&
                    claims.at("aud") == audience && claims.at("nonce") == nonce && claims.at("email_verified") == true &&
                    claims.at("exp").is_number_integer() && claims.at("iat").is_number_integer() &&
                    claims.at("exp").get<int64_t>() > epochSeconds() && claims.at("iat").get<int64_t>() <= epochSeconds() &&
                    !claims.at("sub").get<std::string>().empty() && (!claims.contains("azp") || claims.at("azp") == audience),
                "Invalid provider identity");
        return claims;
    }

    JwtVerifier::JwtVerifier(const std::string& issuer, const std::string& audience, const std::string& publicKeyPem)
        : issuer_(issuer)
        , audience_(audience)
        , publicKeyPem_(publicKeyPem) {
    }

    bool JwtVerifier::verify(const std::string& token, JwtClaims& outClaims, std::string& error, const std::string& purpose) {
        bool valid = false;
        outClaims = {};
        error.clear();
        try {
            const auto payload = verifiedJwt(token, publicKeyPem_);
            const auto header = Json::parse(decodeBase64Url(token.substr(0, token.find('.'))));
            require(header.at("typ") == (purpose == "access" ? "at+jwt" : "JWT"), "Invalid token purpose");
            require(payload.at("iss") == issuer_ && payload.at("aud") == audience_ && payload.at("token_use") == purpose,
                    "Invalid token issuer, audience or purpose");
            require(payload.at("exp").is_number_integer() && payload.at("iat").is_number_integer() && payload.at("nbf").is_number_integer(),
                    "Invalid token times");
            const auto now = epochSeconds();
            const auto expiry = payload.at("exp").get<int64_t>();
            require(expiry > now && payload.at("nbf").get<int64_t>() <= now && payload.at("iat").get<int64_t>() <= now,
                    "Token expired or not yet valid");
            JwtClaims claims;
            claims.subject = payload.at("sub").get<std::string>();
            claims.sessionId = payload.at("sid").get<std::string>();
            require(!claims.subject.empty() && !claims.sessionId.empty(), "Missing identity/session");
            claims.username = payload.value("username", std::string());
            claims.email = payload.value("email", std::string());
            claims.scopes = payload.at("scope").get<std::vector<std::string>>();
            claims.mfaVerified = payload.at("mfa_verified").get<bool>();
            claims.nonce = payload.value("nonce", std::string());
            claims.purpose = purpose;
            claims.issuer = issuer_;
            claims.audience = audience_;
            claims.expiresAt = std::chrono::system_clock::time_point(std::chrono::seconds(expiry));
            outClaims = std::move(claims);
            valid = true;
        } catch (const std::exception&) {
            error = "Invalid authentication token";
        }
        return valid;
    }
} // namespace snodec::auth
