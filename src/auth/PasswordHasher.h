/*
 * SNode.C SSO/MFA — Password Hasher (PBKDF2-HMAC-SHA256)
 * Copyright (C) Jan Nicolas Eberwein 2025/2026 — Master Thesis
 *
 * Secure password hashing using PBKDF2-HMAC-SHA256 via OpenSSL.
 * Format: $pbkdf2-sha256$<iterations>$<salt_b64>$<hash_b64>
 *
 * Supports automatic migration from legacy SHA-256+salt hashes.
 * No additional dependencies beyond OpenSSL (available on OpenWRT).
 */

#pragma once

#include <cstdint>
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace snodec {
    namespace auth {

        class PasswordHasher {
        public:
            // Default iteration count: OWASP minimum for PBKDF2-SHA256 on constrained devices.
            // NIST SP 800-132 recommends >= 1000; OWASP 2023 recommends 600,000 for servers.
            // 100,000 is a practical compromise for ARM-based OpenWRT routers (~200ms on MT7981B).
            static constexpr int DEFAULT_ITERATIONS = 100000;
            static constexpr int SALT_LENGTH = 16; // 128-bit salt
            static constexpr int HASH_LENGTH = 32; // 256-bit derived key
            static constexpr const char* PREFIX = "$pbkdf2-sha256$";

            /**
             * Hash a password with PBKDF2-HMAC-SHA256.
             * Generates a random salt and returns a self-describing hash string.
             *
             * Format: $pbkdf2-sha256$<iterations>$<salt_hex>$<hash_hex>
             */
            static std::string hashPassword(const std::string& password, int iterations = DEFAULT_ITERATIONS) {
                // Generate random salt
                std::vector<unsigned char> salt(SALT_LENGTH);
                if (RAND_bytes(salt.data(), SALT_LENGTH) != 1) {
                    throw std::runtime_error("PasswordHasher: RAND_bytes failed");
                }

                // Derive key using PBKDF2
                std::vector<unsigned char> derivedKey(HASH_LENGTH);
                if (PKCS5_PBKDF2_HMAC(password.c_str(),
                                      static_cast<int>(password.length()),
                                      salt.data(),
                                      SALT_LENGTH,
                                      iterations,
                                      EVP_sha256(),
                                      HASH_LENGTH,
                                      derivedKey.data()) != 1) {
                    throw std::runtime_error("PasswordHasher: PKCS5_PBKDF2_HMAC failed");
                }

                // Encode as self-describing string
                return std::string(PREFIX) + std::to_string(iterations) + "$" + toHex(salt) + "$" + toHex(derivedKey);
            }

            /**
             * Verify a password against a stored PBKDF2 hash string.
             */
            static bool verifyPassword(const std::string& password, const std::string& storedHash) {
                // Parse the stored hash
                if (storedHash.rfind(PREFIX, 0) != 0) {
                    return false; // Not a PBKDF2 hash
                }

                std::string rest = storedHash.substr(std::string(PREFIX).length());
                auto parts = split(rest, '$');
                if (parts.size() != 3) {
                    return false;
                }

                int iterations = std::stoi(parts[0]);
                auto salt = fromHex(parts[1]);
                auto expectedHash = fromHex(parts[2]);

                // Derive key from provided password
                std::vector<unsigned char> derivedKey(HASH_LENGTH);
                if (PKCS5_PBKDF2_HMAC(password.c_str(),
                                      static_cast<int>(password.length()),
                                      salt.data(),
                                      static_cast<int>(salt.size()),
                                      iterations,
                                      EVP_sha256(),
                                      HASH_LENGTH,
                                      derivedKey.data()) != 1) {
                    return false;
                }

                // Constant-time comparison to prevent timing attacks
                return CRYPTO_memcmp(derivedKey.data(), expectedHash.data(), std::min(derivedKey.size(), expectedHash.size())) == 0 &&
                       derivedKey.size() == expectedHash.size();
            }

            /**
             * Check if a stored hash is in the legacy SHA-256 format.
             * Legacy format: 64 hex characters (no prefix).
             */
            static bool isLegacyHash(const std::string& storedHash) {
                if (storedHash.length() != 64)
                    return false;
                for (char c : storedHash) {
                    if (!std::isxdigit(static_cast<unsigned char>(c)))
                        return false;
                }
                return true;
            }

            /**
             * Verify a password against a legacy SHA-256+salt hash.
             * Used during migration: if verification succeeds, the caller should
             * re-hash with hashPassword() and update the database.
             */
            static bool verifyLegacy(const std::string& password, const std::string& storedHash, const std::string& salt) {
                unsigned char hash[SHA256_DIGEST_LENGTH];
                std::string input = password + salt;
                SHA256(reinterpret_cast<const unsigned char*>(input.data()), input.size(), hash);

                std::ostringstream ss;
                for (auto b : hash) {
                    ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
                }

                // Constant-time comparison
                std::string computed = ss.str();
                if (computed.size() != storedHash.size())
                    return false;
                return CRYPTO_memcmp(computed.data(), storedHash.data(), computed.size()) == 0;
            }

        private:
            static std::string toHex(const std::vector<unsigned char>& data) {
                std::ostringstream ss;
                for (auto b : data) {
                    ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
                }
                return ss.str();
            }

            static std::vector<unsigned char> fromHex(const std::string& hex) {
                std::vector<unsigned char> bytes;
                for (size_t i = 0; i + 1 < hex.length(); i += 2) {
                    bytes.push_back(static_cast<unsigned char>(std::strtol(hex.substr(i, 2).c_str(), nullptr, 16)));
                }
                return bytes;
            }

            static std::vector<std::string> split(const std::string& s, char delim) {
                std::vector<std::string> parts;
                std::istringstream ss(s);
                std::string token;
                while (std::getline(ss, token, delim)) {
                    parts.push_back(token);
                }
                return parts;
            }
        };

    } // namespace auth
} // namespace snodec
