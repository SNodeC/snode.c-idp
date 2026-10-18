/*
 * SNode.C SSO/MFA — Secret Encryptor (AES-256-GCM)
 * Copyright (C) Jan Nicolas Eberwein 2025/2026 — Master Thesis
 *
 * Encryption-at-rest for sensitive database fields (TOTP secrets).
 * Uses AES-256-GCM via OpenSSL with a 256-bit key stored in a
 * root-only file (chmod 600).
 *
 * Encrypted format: <iv_hex>:<ciphertext_hex>:<tag_hex>
 * This format is self-describing and supports key rotation by
 * re-encrypting all secrets with a new key.
 *
 * Threat model:
 * - Protects against SQLite database file theft (attacker reads DB
 *   but cannot read the key file due to filesystem permissions).
 * - Does NOT protect against full root compromise (key + DB accessible).
 * - For full root compromise, disk encryption (dm-crypt) is recommended.
 */

#pragma once

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sys/stat.h>

#include <cstring>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace snodec {
    namespace auth {

        class SecretEncryptor {
        public:
            static constexpr int KEY_LENGTH = 32;  // 256-bit key
            static constexpr int IV_LENGTH = 12;   // 96-bit IV (recommended for GCM)
            static constexpr int TAG_LENGTH = 16;  // 128-bit authentication tag

            /**
             * Generate a new random encryption key and write it to a file.
             * The file is created with restrictive permissions (owner read/write only).
             */
            static void generateKeyFile(const std::string& keyPath) {
                std::vector<unsigned char> key(KEY_LENGTH);
                if (RAND_bytes(key.data(), KEY_LENGTH) != 1) {
                    throw std::runtime_error("SecretEncryptor: RAND_bytes failed for key generation");
                }

                std::ofstream f(keyPath, std::ios::binary | std::ios::trunc);
                if (!f.is_open()) {
                    throw std::runtime_error("SecretEncryptor: cannot create key file: " + keyPath);
                }
                f.write(reinterpret_cast<const char*>(key.data()), KEY_LENGTH);
                f.close();

                // Set restrictive permissions (Unix only)
#ifndef _WIN32
                chmod(keyPath.c_str(), 0600);
#endif
            }

            /**
             * Encrypt a plaintext string using AES-256-GCM.
             * Returns: <iv_hex>:<ciphertext_hex>:<tag_hex>
             */
            static std::string encrypt(const std::string& plaintext, const std::string& keyPath) {
                auto key = loadKey(keyPath);

                // Generate random IV
                std::vector<unsigned char> iv(IV_LENGTH);
                if (RAND_bytes(iv.data(), IV_LENGTH) != 1) {
                    throw std::runtime_error("SecretEncryptor: RAND_bytes failed for IV");
                }

                // Encrypt
                EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
                if (!ctx) throw std::runtime_error("SecretEncryptor: EVP_CIPHER_CTX_new failed");

                if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
                    EVP_CIPHER_CTX_free(ctx);
                    throw std::runtime_error("SecretEncryptor: EncryptInit failed");
                }

                if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LENGTH, nullptr) != 1) {
                    EVP_CIPHER_CTX_free(ctx);
                    throw std::runtime_error("SecretEncryptor: set IV length failed");
                }

                if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1) {
                    EVP_CIPHER_CTX_free(ctx);
                    throw std::runtime_error("SecretEncryptor: EncryptInit with key/IV failed");
                }

                std::vector<unsigned char> ciphertext(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
                int len = 0;
                if (EVP_EncryptUpdate(ctx,
                                      ciphertext.data(), &len,
                                      reinterpret_cast<const unsigned char*>(plaintext.data()),
                                      static_cast<int>(plaintext.size())) != 1) {
                    EVP_CIPHER_CTX_free(ctx);
                    throw std::runtime_error("SecretEncryptor: EncryptUpdate failed");
                }
                int ciphertextLen = len;

                if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
                    EVP_CIPHER_CTX_free(ctx);
                    throw std::runtime_error("SecretEncryptor: EncryptFinal failed");
                }
                ciphertextLen += len;
                ciphertext.resize(ciphertextLen);

                // Get authentication tag
                std::vector<unsigned char> tag(TAG_LENGTH);
                if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LENGTH, tag.data()) != 1) {
                    EVP_CIPHER_CTX_free(ctx);
                    throw std::runtime_error("SecretEncryptor: get tag failed");
                }

                EVP_CIPHER_CTX_free(ctx);

                // Return formatted string: iv:ciphertext:tag
                return toHex(iv) + ":" + toHex(ciphertext) + ":" + toHex(tag);
            }

            /**
             * Decrypt an encrypted string using AES-256-GCM.
             * Input format: <iv_hex>:<ciphertext_hex>:<tag_hex>
             * Returns the plaintext on success, throws on failure.
             */
            static std::string decrypt(const std::string& encrypted, const std::string& keyPath) {
                auto key = loadKey(keyPath);

                // Parse the encrypted format
                auto parts = split(encrypted, ':');
                if (parts.size() != 3) {
                    throw std::runtime_error("SecretEncryptor: invalid encrypted format (expected iv:ct:tag)");
                }

                auto iv = fromHex(parts[0]);
                auto ciphertext = fromHex(parts[1]);
                auto tag = fromHex(parts[2]);

                if (iv.size() != IV_LENGTH || tag.size() != TAG_LENGTH) {
                    throw std::runtime_error("SecretEncryptor: invalid IV or tag length");
                }

                // Decrypt
                EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
                if (!ctx) throw std::runtime_error("SecretEncryptor: EVP_CIPHER_CTX_new failed");

                if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
                    EVP_CIPHER_CTX_free(ctx);
                    throw std::runtime_error("SecretEncryptor: DecryptInit failed");
                }

                if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LENGTH, nullptr) != 1) {
                    EVP_CIPHER_CTX_free(ctx);
                    throw std::runtime_error("SecretEncryptor: set IV length failed");
                }

                if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1) {
                    EVP_CIPHER_CTX_free(ctx);
                    throw std::runtime_error("SecretEncryptor: DecryptInit with key/IV failed");
                }

                std::vector<unsigned char> plaintext(ciphertext.size() + EVP_MAX_BLOCK_LENGTH);
                int len = 0;
                if (EVP_DecryptUpdate(ctx,
                                      plaintext.data(), &len,
                                      ciphertext.data(),
                                      static_cast<int>(ciphertext.size())) != 1) {
                    EVP_CIPHER_CTX_free(ctx);
                    throw std::runtime_error("SecretEncryptor: DecryptUpdate failed");
                }
                int plaintextLen = len;

                // Set expected tag
                if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LENGTH,
                                        const_cast<unsigned char*>(tag.data())) != 1) {
                    EVP_CIPHER_CTX_free(ctx);
                    throw std::runtime_error("SecretEncryptor: set tag failed");
                }

                // Finalize — this verifies the authentication tag
                if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
                    EVP_CIPHER_CTX_free(ctx);
                    throw std::runtime_error("SecretEncryptor: authentication tag verification failed — data may be tampered");
                }
                plaintextLen += len;

                EVP_CIPHER_CTX_free(ctx);

                return std::string(reinterpret_cast<char*>(plaintext.data()), plaintextLen);
            }

            /**
             * Check if a stored value is encrypted (contains the iv:ct:tag format)
             * vs plaintext Base32 (legacy unencrypted format).
             */
            static bool isEncrypted(const std::string& value) {
                // Encrypted format contains exactly two colons separating hex strings
                auto parts = split(value, ':');
                if (parts.size() != 3) return false;
                // Check that all parts are hex
                for (const auto& p : parts) {
                    if (p.empty()) return false;
                    for (char c : p) {
                        if (!std::isxdigit(static_cast<unsigned char>(c))) return false;
                    }
                }
                return true;
            }

            /**
             * Load a key from a file. The key file must contain exactly KEY_LENGTH bytes.
             */
            static std::vector<unsigned char> loadKey(const std::string& keyPath) {
                std::ifstream f(keyPath, std::ios::binary);
                if (!f.is_open()) {
                    throw std::runtime_error("SecretEncryptor: cannot open key file: " + keyPath);
                }
                std::vector<unsigned char> key(KEY_LENGTH);
                f.read(reinterpret_cast<char*>(key.data()), KEY_LENGTH);
                if (f.gcount() != KEY_LENGTH || f.peek() != std::char_traits<char>::eof()) {
                    throw std::runtime_error("SecretEncryptor: key file must contain exactly " + std::to_string(KEY_LENGTH) + " bytes");
                }
                return key;
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
                if (hex.size() % 2 != 0 || hex.find_first_not_of("0123456789abcdefABCDEF") != std::string::npos) {
                    throw std::runtime_error("SecretEncryptor: invalid hex encoding");
                }
                for (size_t i = 0; i + 1 < hex.length(); i += 2) {
                    bytes.push_back(static_cast<unsigned char>(
                        std::strtol(hex.substr(i, 2).c_str(), nullptr, 16)));
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
