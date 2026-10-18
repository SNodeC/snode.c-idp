#ifndef AUTH_TOTP_H
#define AUTH_TOTP_H

#include <cstdint>
#include <string>
#include <vector>

namespace snodec {
    namespace auth {

        class Totp {
        public:
            // Generate a random Base32-encoded secret (160 bits / 20 bytes)
            static std::string generateSecret();

            // Generate TOTP code for current time
            static std::string generateCode(const std::string& base32Secret, uint64_t timeStep = 30);

            // Generate TOTP code for specific timestamp
            static std::string generateCodeAt(const std::string& base32Secret, uint64_t timestamp, uint64_t timeStep = 30);

            // Verify TOTP code with ±1 time-step drift tolerance
            static bool verifyCode(const std::string& base32Secret, const std::string& code, uint64_t timeStep = 30, int driftSteps = 1);

            // Generate otpauth:// URI for QR code
            static std::string
            generateOtpAuthUri(const std::string& base32Secret, const std::string& username, const std::string& issuer = "SNodeC");

        private:
            // Base32 encoding/decoding
            static std::string base32Encode(const std::vector<uint8_t>& data);
            static std::vector<uint8_t> base32Decode(const std::string& encoded);

            // TOTP algorithm
            static uint32_t generateTotpValue(const std::vector<uint8_t>& secret, uint64_t timeCounter);
        };

    } // namespace auth
} // namespace snodec

#endif // AUTH_TOTP_H
