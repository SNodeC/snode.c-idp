#include "QrCodeGenerator.h"

#include "../supplement/qrcodegen/qrcodegen.hpp"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <iostream>
#include <stdexcept>

namespace snodec {
    namespace auth {

        // =============================================================================
        // Public Interface
        // =============================================================================

        std::vector<uint8_t> QrCodeGenerator::generatePng(const std::string& data, int moduleSize, int margin) {
            auto m = generateMatrix(data);
            return encodePng(m, moduleSize, margin);
        }

        std::string QrCodeGenerator::generateDataUri(const std::string& data, int moduleSize, int margin) {
            auto png = generatePng(data, moduleSize, margin);
            return "data:image/png;base64," + base64Encode(png);
        }

        std::string QrCodeGenerator::makeTotpOtpAuthUri(const std::string& issuer,
                                                        const std::string& accountName,
                                                        const std::string& secretBase32,
                                                        int digits,
                                                        int period,
                                                        const std::string& algorithm) {
            // Use a clean issuer name for maximum compatibility
            std::string safeIssuer = issuer;
            if (safeIssuer == "SNode.C") safeIssuer = "SNodeC";
            
            // Standard format: otpauth://totp/Issuer:Account?secret=...&issuer=Issuer
            // We encode issuer and account name separately to keep the ':' literal in the path.
            std::string uri = "otpauth://totp/" + urlEncode(safeIssuer) + ":" + urlEncode(accountName) + 
                              "?secret=" + urlEncode(secretBase32) + 
                              "&issuer=" + urlEncode(safeIssuer);
                              
            if (algorithm != "SHA1") uri += "&algorithm=" + urlEncode(algorithm);
            if (digits != 6) uri += "&digits=" + std::to_string(digits);
            if (period != 30) uri += "&period=" + std::to_string(period);

            return uri;
        }

        // =============================================================================
        // Matrix Generation (using Nayuki qrcodegen)
        // =============================================================================

        std::vector<std::vector<bool>> QrCodeGenerator::generateMatrix(const std::string& data) {
            using namespace qrcodegen;
            try {
                // Use MEDIUM error correction as a sane default
                QrCode qr = QrCode::encodeText(data.c_str(), QrCode::Ecc::MEDIUM);
                int size = qr.getSize();

                std::vector<std::vector<bool>> m(size, std::vector<bool>(size));
                for (int r = 0; r < size; r++) {
                    for (int c = 0; c < size; c++) {
                        m[r][c] = qr.getModule(c, r);
                    }
                }
                return m;
            } catch (const std::exception& e) {
                // Handle potential errors (e.g. data too long)
                throw std::runtime_error(std::string("QR generation failed: ") + e.what());
            }
        }

        // =============================================================================
        // PNG encoding (grayscale 8-bit, filter 0, zlib stored blocks)
        // =============================================================================

        std::vector<uint8_t> QrCodeGenerator::encodePng(const std::vector<std::vector<bool>>& matrix, int moduleSize, int margin) {
            int qrSize = (int) matrix.size();
            int imgSize = (qrSize + margin * 2) * moduleSize;

            // raw image bytes with filter byte per scanline
            std::vector<uint8_t> raw;
            raw.reserve((size_t) imgSize * (imgSize + 1));

            for (int y = 0; y < imgSize; y++) {
                raw.push_back(0x00); // filter type 0
                for (int x = 0; x < imgSize; x++) {
                    int r = (y / moduleSize) - margin;
                    int c = (x / moduleSize) - margin;
                    bool dark = false;
                    if (r >= 0 && r < qrSize && c >= 0 && c < qrSize)
                        dark = matrix[r][c];
                    raw.push_back(dark ? 0x00 : 0xFF);
                }
            }

            auto idat = deflateStoredZlib(raw);

            std::vector<uint8_t> png{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};

            auto writeChunk = [&](const char type[4], const std::vector<uint8_t>& data) {
                uint32_t len = (uint32_t) data.size();
                png.push_back(static_cast<uint8_t>(len >> 24));
                png.push_back(static_cast<uint8_t>(len >> 16));
                png.push_back(static_cast<uint8_t>(len >> 8));
                png.push_back(static_cast<uint8_t>(len));

                png.push_back(type[0]);
                png.push_back(type[1]);
                png.push_back(type[2]);
                png.push_back(type[3]);
                png.insert(png.end(), data.begin(), data.end());

                std::vector<uint8_t> crcData;
                crcData.push_back(type[0]);
                crcData.push_back(type[1]);
                crcData.push_back(type[2]);
                crcData.push_back(type[3]);
                crcData.insert(crcData.end(), data.begin(), data.end());

                uint32_t crc = crc32(crcData);
                png.push_back(static_cast<uint8_t>(crc >> 24));
                png.push_back(static_cast<uint8_t>(crc >> 16));
                png.push_back(static_cast<uint8_t>(crc >> 8));
                png.push_back(static_cast<uint8_t>(crc));
            };

            // IHDR
            std::vector<uint8_t> ihdr;
            ihdr.reserve(13);
            auto put32 = [&](uint32_t v) {
                ihdr.push_back(static_cast<uint8_t>(v >> 24));
                ihdr.push_back(static_cast<uint8_t>(v >> 16));
                ihdr.push_back(static_cast<uint8_t>(v >> 8));
                ihdr.push_back(static_cast<uint8_t>(v));
            };
            put32((uint32_t) imgSize); // width
            put32((uint32_t) imgSize); // height
            ihdr.push_back(8);         // bit depth
            ihdr.push_back(0);         // color type: grayscale
            ihdr.push_back(0);         // compression
            ihdr.push_back(0);         // filter
            ihdr.push_back(0);         // interlace
            writeChunk("IHDR", ihdr);

            // IDAT
            writeChunk("IDAT", idat);

            // IEND
            writeChunk("IEND", {});

            return png;
        }

        std::vector<uint8_t> QrCodeGenerator::deflateStoredZlib(const std::vector<uint8_t>& data) {
            // zlib header for "no compression/fastest", valid check bits
            std::vector<uint8_t> out{0x78, 0x01};
            out.reserve(data.size() + 16 + (data.size() / 65535 + 1) * 5);

            size_t pos = 0;
            while (pos < data.size()) {
                size_t remaining = data.size() - pos;
                uint16_t blockLen = (uint16_t) std::min<size_t>(remaining, 65535);
                bool last = (pos + blockLen) >= data.size();

                // Stored block header: BFINAL + BTYPE=00 in low 3 bits, rest 0
                out.push_back(last ? 0x01 : 0x00);

                // LEN, NLEN
                out.push_back(static_cast<uint8_t>(blockLen));
                out.push_back(static_cast<uint8_t>(blockLen >> 8));
                uint16_t nlen = (uint16_t) ~blockLen;
                out.push_back(static_cast<uint8_t>(nlen));
                out.push_back(static_cast<uint8_t>(nlen >> 8));

                // payload
                out.insert(out.end(), data.begin() + pos, data.begin() + pos + blockLen);
                pos += blockLen;
            }

            // Adler32
            uint32_t s1 = 1, s2 = 0;
            for (uint8_t b : data) {
                s1 = (s1 + b) % 65521;
                s2 = (s2 + s1) % 65521;
            }
            uint32_t adler = (s2 << 16) | s1;
            out.push_back(static_cast<uint8_t>(adler >> 24));
            out.push_back(static_cast<uint8_t>(adler >> 16));
            out.push_back(static_cast<uint8_t>(adler >> 8));
            out.push_back(static_cast<uint8_t>(adler));

            return out;
        }

        uint32_t QrCodeGenerator::crc32(const std::vector<uint8_t>& data) {
            static uint32_t table[256];
            static bool init = false;

            if (!init) {
                for (uint32_t i = 0; i < 256; i++) {
                    uint32_t c = i;
                    for (int k = 0; k < 8; k++) {
                        c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
                    }
                    table[i] = c;
                }
                init = true;
            }

            uint32_t crc = 0xFFFFFFFFu;
            for (uint8_t b : data) {
                crc = table[(crc ^ b) & 0xFFu] ^ (crc >> 8);
            }
            return crc ^ 0xFFFFFFFFu;
        }

        std::string QrCodeGenerator::base64Encode(const std::vector<uint8_t>& data) {
            static const char* chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            std::string out;
            out.reserve((data.size() + 2) / 3 * 4);

            for (size_t i = 0; i < data.size(); i += 3) {
                uint32_t n = (uint32_t) data[i] << 16;
                if (i + 1 < data.size())
                    n |= (uint32_t) data[i + 1] << 8;
                if (i + 2 < data.size())
                    n |= (uint32_t) data[i + 2];

                out.push_back(chars[(n >> 18) & 0x3F]);
                out.push_back(chars[(n >> 12) & 0x3F]);
                out.push_back((i + 1 < data.size()) ? chars[(n >> 6) & 0x3F] : '=');
                out.push_back((i + 2 < data.size()) ? chars[n & 0x3F] : '=');
            }

            return out;
        }

        std::string QrCodeGenerator::urlEncode(const std::string& s) {
            static const char hex[] = "0123456789ABCDEF";
            std::string out;
            for (unsigned char ch : s) {
                if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' ||
                    ch == '.' || ch == '~' || ch == ':') {
                    out.push_back((char) ch);
                } else if (ch == ' ') {
                    out.push_back('%');
                    out.push_back('2');
                    out.push_back('0');
                } else {
                    out.push_back('%');
                    out.push_back(hex[(ch >> 4) & 0xF]);
                    out.push_back(hex[ch & 0xF]);
                }
            }
            return out;
        }

        void QrCodeGenerator::secureWipe(std::vector<uint8_t>& v) {
            volatile uint8_t* p = v.data();
            for (size_t i = 0; i < v.size(); i++)
                p[i] = 0;
            v.clear();
            v.shrink_to_fit();
        }

    } // namespace auth
} // namespace snodec
