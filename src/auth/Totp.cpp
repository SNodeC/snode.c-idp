#include "Totp.h"

#include <algorithm>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sstream>
#include <stdexcept>

namespace snodec {
    namespace auth {

        // Base32 alphabet (RFC 4648)
        static const char base32Alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

        std::string Totp::generateSecret() {
            std::vector<uint8_t> randomBytes(20); // 160 bits
            if (RAND_bytes_ex(nullptr, randomBytes.data(), randomBytes.size(), 0) != 1) {
                throw std::runtime_error("Failed to generate random bytes");
            }
            return base32Encode(randomBytes);
        }

        std::string Totp::base32Encode(const std::vector<uint8_t>& data) {
            std::string result;
            uint32_t buffer = 0;
            int bitsLeft = 0;

            for (uint8_t byte : data) {
                buffer = (buffer << 8) | byte;
                bitsLeft += 8;

                while (bitsLeft >= 5) {
                    int index = (buffer >> (bitsLeft - 5)) & 0x1F;
                    result += base32Alphabet[index];
                    bitsLeft -= 5;
                }
            }

            if (bitsLeft > 0) {
                int index = (buffer << (5 - bitsLeft)) & 0x1F;
                result += base32Alphabet[index];
            }

            return result;
        }

        std::vector<uint8_t> Totp::base32Decode(const std::string& encoded) {
            std::vector<uint8_t> result;
            uint32_t buffer = 0;
            int bitsLeft = 0;

            for (char c : encoded) {
                if (c == '=' || c == ' ' || c == '\n' || c == '\r') {
                    continue; // Skip padding and whitespace
                }

                // Find character in alphabet
                int value = -1;
                for (int i = 0; i < 32; i++) {
                    if (base32Alphabet[i] == c || base32Alphabet[i] == (c - 32)) { // Handle lowercase
                        value = i;
                        break;
                    }
                }

                if (value == -1) {
                    throw std::runtime_error("Invalid Base32 character");
                }

                buffer = (buffer << 5) | value;
                bitsLeft += 5;

                if (bitsLeft >= 8) {
                    result.push_back(static_cast<uint8_t>(buffer >> (bitsLeft - 8)));
                    bitsLeft -= 8;
                }
            }

            return result;
        }

        uint32_t Totp::generateTotpValue(const std::vector<uint8_t>& secret, uint64_t timeCounter) {
            // Convert time counter to 8-byte array (big-endian)
            std::vector<uint8_t> message(8);
            for (int i = 7; i >= 0; i--) {
                message[i] = timeCounter & 0xFF;
                timeCounter >>= 8;
            }

            // Calculate HMAC-SHA1
            unsigned char hash[20];
            if (EVP_Q_mac(nullptr,
                          "HMAC",
                          nullptr,
                          "SHA1",
                          nullptr,
                          secret.data(),
                          secret.size(),
                          message.data(),
                          message.size(),
                          hash,
                          sizeof(hash),
                          nullptr) == nullptr) {
                throw std::runtime_error("Failed to compute HMAC-SHA1");
            }

            // Dynamic truncation (RFC 6238)
            int offset = hash[sizeof(hash) - 1] & 0x0F;
            uint32_t code = ((hash[offset] & 0x7F) << 24) | ((hash[offset + 1] & 0xFF) << 16) | ((hash[offset + 2] & 0xFF) << 8) |
                            (hash[offset + 3] & 0xFF);

            // Return 6-digit code
            return code % 1000000;
        }

        std::string Totp::generateCode(const std::string& base32Secret, uint64_t timeStep) {
            uint64_t timestamp = static_cast<uint64_t>(std::time(nullptr));
            return generateCodeAt(base32Secret, timestamp, timeStep);
        }

        std::string Totp::generateCodeAt(const std::string& base32Secret, uint64_t timestamp, uint64_t timeStep) {
            std::vector<uint8_t> secret = base32Decode(base32Secret);
            uint64_t timeCounter = timestamp / timeStep;
            uint32_t code = generateTotpValue(secret, timeCounter);

            // Format as 6-digit string with leading zeros
            std::ostringstream oss;
            oss << std::setfill('0') << std::setw(6) << code;
            return oss.str();
        }

        bool Totp::verifyCode(const std::string& base32Secret, const std::string& code, uint64_t timeStep, int driftSteps) {
            uint64_t currentTime = static_cast<uint64_t>(std::time(nullptr));
            uint64_t currentCounter = currentTime / timeStep;

            // Check current time and ±driftSteps
            for (int i = -driftSteps; i <= driftSteps; i++) {
                uint64_t counter = currentCounter + i;
                std::string expectedCode = generateCodeAt(base32Secret, counter * timeStep, timeStep);

                if (code == expectedCode) {
                    return true;
                }
            }

            return false;
        }

        std::string Totp::generateOtpAuthUri(const std::string& base32Secret, const std::string& username, const std::string& issuer) {
            std::string cleanSecret = base32Secret;
            cleanSecret.erase(std::remove(cleanSecret.begin(), cleanSecret.end(), '='), cleanSecret.end());
            
            std::ostringstream uri;
            uri << "otpauth://totp/" << issuer << ":" << username << "?secret=" << cleanSecret << "&issuer=" << issuer << "&algorithm=SHA1"
                << "&digits=6"
                << "&period=30";
            return uri.str();
        }

    } // namespace auth
} // namespace snodec
