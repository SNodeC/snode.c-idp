#include "auth/QrCodeGenerator.h"
#include "auth/Totp.h"

#include <array>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>

int main(int argc, char** argv) {
    int status = 0;
    try {
        if (argc != 2) {
            throw std::runtime_error("Expected output prefix");
        }
        const std::string secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        const std::array<uint64_t, 6> times = {59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000};
        const std::array<std::string, 6> expected = {"287082", "081804", "050471", "005924", "279037", "353130"};
        for (size_t i = 0; i < times.size(); ++i) {
            if (snodec::auth::Totp::generateCodeAt(secret, times[i]) != expected[i]) {
                throw std::runtime_error("RFC 6238 SHA-1 vector failed (six-digit truncation)");
            }
        }
        const auto generated = snodec::auth::Totp::generateSecret();
        if (generated.size() != 32 || generated.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") != std::string::npos) {
            throw std::runtime_error("Invalid generated secret");
        }
        for (int scale : {1, 16}) {
            const auto png = snodec::auth::QrCodeGenerator::generatePng(secret, scale, 4);
            const std::string prefix = std::string(argv[1]) + std::to_string(scale);
            std::ofstream output(prefix + ".png", std::ios::binary);
            output.write(reinterpret_cast<const char*>(png.data()), static_cast<std::streamsize>(png.size()));
            const auto matrix = snodec::auth::QrCodeGenerator::generateMatrix(secret);
            std::ofstream modules(prefix + ".matrix");
            for (const auto& row : matrix) {
                for (bool dark : row) {
                    modules << (dark ? '1' : '0');
                }
                modules << '\n';
            }
            if (!output || !modules) {
                throw std::runtime_error("Failed to write encoding fixtures");
            }
        }
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        status = 1;
    }
    return status;
}
