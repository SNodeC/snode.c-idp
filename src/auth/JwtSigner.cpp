#include "JwtSigner.h"

#include "Security.h"

#include <memory>
#include <openssl/pem.h>
#include <openssl/rsa.h>

namespace snodec::auth {
    JwtSigner::JwtSigner(const std::string& issuer, const std::string& privateKeyPem)
        : issuer_(issuer)
        , privateKeyPem_(privateKeyPem) {
        std::unique_ptr<BIO, decltype(&BIO_free)> input(BIO_new_mem_buf(privateKeyPem.data(), static_cast<int>(privateKeyPem.size())),
                                                        BIO_free);
        require(input != nullptr, "Invalid signing key");
        std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(PEM_read_bio_PrivateKey(input.get(), nullptr, nullptr, nullptr),
                                                                EVP_PKEY_free);
        require(key && EVP_PKEY_is_a(key.get(), "RSA") == 1 && EVP_PKEY_get_bits(key.get()) >= 2048,
                "RSA key must have at least 2048 bits");
        Json jwk = {{"kty", "RSA"}};
        for (const auto* name : {"e", "n"}) {
            BIGNUM* raw = nullptr;
            require(EVP_PKEY_get_bn_param(key.get(), name, &raw) == 1, "Invalid RSA key");
            std::unique_ptr<BIGNUM, decltype(&BN_free)> value(raw, BN_free);
            std::string bytes(static_cast<size_t>(BN_num_bytes(value.get())), '\0');
            BN_bn2bin(value.get(), reinterpret_cast<unsigned char*>(bytes.data()));
            jwk[name] = base64Url(bytes);
        }
        keyId_ = sha256(jwk.dump());
        jwk.update({{"kid", keyId_}, {"use", "sig"}, {"alg", "RS256"}});
        jwks_ = Json({{"keys", Json::array({jwk})}}).dump();
        std::unique_ptr<BIO, decltype(&BIO_free)> output(BIO_new(BIO_s_mem()), BIO_free);
        require(output && PEM_write_bio_PUBKEY(output.get(), key.get()) == 1, "Cannot export public key");
        char* data = nullptr;
        const long length = BIO_get_mem_data(output.get(), &data);
        publicKey_.assign(data, static_cast<size_t>(length));
    }

    std::string JwtSigner::jwks() const {
        return jwks_;
    }

    std::string JwtSigner::publicKey() const {
        return publicKey_;
    }

    std::string JwtSigner::sign(const JwtClaims& claims) {
        require(!claims.sessionId.empty() && (claims.purpose == "access" || claims.purpose == "id"), "Invalid token identity");
        const Json header = {{"alg", "RS256"}, {"typ", claims.purpose == "access" ? "at+jwt" : "JWT"}, {"kid", keyId_}};
        Json payload = {{"iss", issuer_},
                        {"aud", claims.audience},
                        {"sub", claims.subject},
                        {"sid", claims.sessionId},
                        {"exp", std::chrono::duration_cast<std::chrono::seconds>(claims.expiresAt.time_since_epoch()).count()},
                        {"iat", epochSeconds()},
                        {"nbf", epochSeconds()},
                        {"username", claims.username},
                        {"email", claims.email},
                        {"mfa_verified", claims.mfaVerified},
                        {"scope", claims.scopes},
                        {"token_use", claims.purpose}};
        if (claims.purpose == "id" && !claims.nonce.empty()) {
            payload["nonce"] = claims.nonce;
        }
        if (claims.purpose == "id" && claims.mfaVerified) {
            payload["acr"] = "urn:snodec:acr:mfa";
        }
        const std::string input = base64Url(header.dump()) + "." + base64Url(payload.dump());
        std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new_mem_buf(privateKeyPem_.data(), static_cast<int>(privateKeyPem_.size())),
                                                      BIO_free);
        require(bio != nullptr, "Cannot load signing key");
        std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr),
                                                                EVP_PKEY_free);
        std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
        require(key && ctx && EVP_DigestSignInit(ctx.get(), nullptr, EVP_sha256(), nullptr, key.get()) == 1, "Cannot initialize signature");
        size_t length = 0;
        require(EVP_DigestSign(ctx.get(), nullptr, &length, reinterpret_cast<const unsigned char*>(input.data()), input.size()) == 1,
                "Cannot size signature");
        std::string signature(length, '\0');
        require(EVP_DigestSign(ctx.get(),
                               reinterpret_cast<unsigned char*>(signature.data()),
                               &length,
                               reinterpret_cast<const unsigned char*>(input.data()),
                               input.size()) == 1,
                "Cannot sign token");
        signature.resize(length);
        return input + "." + base64Url(signature);
    }
} // namespace snodec::auth
