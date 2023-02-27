/* Copyright 2023 Cambridge Quantum Computing Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "key_writer.h"
#include "key_parameters.h"

#include <qo_decrypt/qo_cleanse.h>

#include <cppcodec/base64_rfc4648.hpp>
#include <cppcodec/hex_upper.hpp>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

namespace Quantinuum::QuantumOrigin::Cli::Utils
{

    KeyWriter::KeyWriter(std::optional<Common::KeyType> keyType) : _keyType(std::move(keyType)) {}

    void KeyWriter::emitResult(std::ostream &outputStream, const std::string &content)
    {
        spdlog::trace("DEBUG: Writing {} bytes", content.size());

        outputStream.write(content.c_str(), content.size());

        // Ensure all data is flushed to the file
        outputStream.flush();
    }

    std::string KeyWriter::jwkEncode(const std::vector<uint8_t> &plainTextOut)
    {
        std::string algorithmString;
        std::string outputString;
        const size_t CHARS_PER_LINE = 64;

        if (_keyType == Common::KeyType{Common::Cli_Alg_Type::KEY_TYPE_AES, Common::Cli_AES_Variant::AES_128})
        {
            algorithmString = "A128KW";
        }
        else if (_keyType == Common::KeyType{Common::Cli_Alg_Type::KEY_TYPE_AES, Common::Cli_AES_Variant::AES_192})
        {
            algorithmString = "A192KW";
        }
        else if (_keyType == Common::KeyType{Common::Cli_Alg_Type::KEY_TYPE_AES, Common::Cli_AES_Variant::AES_256})
        {
            algorithmString = "A256KW";
        }
        else if (!_keyType)
        {
            // Generic
            algorithmString = "UNSPECIFIED";
        }
        else
        {
            auto found = std::find_if(std::begin(Common::supportedKeyTypes), std::end(Common::supportedKeyTypes), [&](auto &&p) { return p.second == _keyType; });

            if (found != Common::supportedKeyTypes.end())
            {
                // All others
                algorithmString = found->first;
            }
            else
            {
                // Generic
                algorithmString = "UNSPECIFIED";
            }
        }

        std::string encodedString = cppcodec::base64_rfc4648::encode(plainTextOut);

        /********************************************************************************************
         ** https://tools.ietf.org/id/draft-jones-jose-json-private-and-symmetric-key-00.html#rfc.section.4
         **
         ** 6. Example Symmetric Keys
         **  The following example JWK Set contains two symmetric keys represented as
         *JWKs: one designated
         **  as being for use with the AES Key Wrap algorithm and a second one that is
         *an HMAC key.
         **  (Line breaks are for display purposes only.)
         **
         **  {
         **    "keys":
         **    [
         **      {
         **       "kty":"oct",
         **       "alg":"A128KW",
         **       "k":"GawgguFyGrWKav7AX4VKUg"
         **      },
         **      {
         **       "kty":"oct",
         **
         *"k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
         **       "kid":"HMAC key used in JWS A.1 example"
         **      }
         **    ]
         **  }
         ********************************************************************************************/

        nlohmann::json jsonOutput = nlohmann::json::parse(R"({"keys": {"kty":"oct"} })");
        jsonOutput["keys"]["alg"] = algorithmString;
        jsonOutput["keys"]["k"]   = encodedString;
        CleanseStdString(encodedString);
        return jsonOutput.dump();
    }

    std::string KeyWriter::pemEncode(const std::vector<uint8_t> &plainTextOut)
    {
        // PEM (Base64 encoded X.509)
        // rfc7468
        // The original plainTextOut value was produced by ClientCrypto at
        // server-side by the pk_write_key_der() function from mbedtls (called by the
        // rust wrapper write_private_der_vec())

        // contentType examples:
        //   AES-256, RSA-2048, EC-SecP192k1,
        //   CLASSIC-MCELIECE-348864, NTRU-HPS-2048-509, KYBER512-90s,
        //   FIRESABER, DILITHIUM2-AES, FALCON-512, RAINBOW-I-CLASSIC

        std::string headerText;
        std::string outputString;
        const size_t CHARS_PER_LINE = 64;

        if (_keyType == Common::KeyType{Common::Cli_Alg_Type::KEY_TYPE_EC, Common::Cli_EC_Variant::X25519})
        {
            // EC-X25519 is treated separately, its not similar to any other EC type key
            headerText = "PRIVATE KEY";
        }
        else if (_keyType && _keyType->algorithm == Common::Cli_Alg_Type::KEY_TYPE_RSA)
        {
            // -----BEGIN RSA PRIVATE KEY-----
            // -----END RSA PRIVATE KEY-----
            headerText = "RSA PRIVATE KEY";
        }
        else if (_keyType && _keyType->algorithm == Common::Cli_Alg_Type::KEY_TYPE_EC)
        {
            // -----BEGIN EC PRIVATE KEY-----
            // -----END EC PRIVATE KEY-----
            headerText = "EC PRIVATE KEY";
        }
        else if (!_keyType)
        {
            // Generic
            headerText = "ENCRYPTION KEY";
        }
        else
        {
            auto found = std::find_if(std::begin(Common::supportedKeyTypes), std::end(Common::supportedKeyTypes), [&](auto &&p) { return p.second == _keyType; });

            if (found != Common::supportedKeyTypes.end())
            {
                // All others
                headerText = found->first + " ENCRYPTION KEY";
            }
            else
            {
                // Generic
                headerText = "ENCRYPTION KEY";
            }
        }

        std::string encodedString = cppcodec::base64_rfc4648::encode(plainTextOut);

        outputString.append(std::string("-----BEGIN ") + headerText + std::string("-----\n"));
        size_t charsRemaining = encodedString.length();
        size_t offset         = 0;
        size_t lineLength;
        while (charsRemaining > 0)
        {
            lineLength = std::min(CHARS_PER_LINE, charsRemaining);
            outputString.append(encodedString.substr(offset, lineLength));
            outputString.append("\n");
            charsRemaining -= lineLength;
            offset += lineLength;
        }
        outputString.append(std::string("-----END ") + headerText + std::string("-----\n"));

        CleanseStdString(encodedString);
        return outputString;
    }

    void KeyWriter::outputKeyData(const std::vector<uint8_t> &plainTextOut, Cli::Commands::OutputFormat outputFormat, std::ostream &outputStream)
    {
        //////////////////////////////////////////////////////////////////////////////////////////////////////////
        // Create Output
        // OutputFormat: pem, jwk, base64, hex or raw. Default=pem for asymmetric keys, jwk for symmetric keys.
        //////////////////////////////////////////////////////////////////////////////////////////////////////////
        if (outputFormat == Cli::Commands::OutputFormat::Jwk)
        {
            spdlog::info("Emitting JSON/JWK");
            std::string encodedString = jwkEncode(plainTextOut);
            emitResult(outputStream, encodedString);
            CleanseStdString(encodedString);
        }
        else if (outputFormat == Cli::Commands::OutputFormat::Pem)
        {
            spdlog::info("Emitting PEM");
            std::string encodedString = pemEncode(plainTextOut);
            emitResult(outputStream, encodedString);
            CleanseStdString(encodedString);
        }
        else if (outputFormat == Cli::Commands::OutputFormat::Base64)
        {
            spdlog::info("Emitting Base64");
            std::string encodedString = cppcodec::base64_rfc4648::encode(plainTextOut);
            emitResult(outputStream, encodedString);
            CleanseStdString(encodedString);
        }
        else if (outputFormat == Cli::Commands::OutputFormat::Hex)
        {
            spdlog::info("Emitting HEX");
            std::string encodedString = cppcodec::hex_upper::encode(plainTextOut);
            emitResult(outputStream, encodedString);
            CleanseStdString(encodedString);
        }
        else if (outputFormat == Cli::Commands::OutputFormat::Binary)
        {
            spdlog::info("Emitting RAW");
            std::string content((const char *)plainTextOut.data(), plainTextOut.size());
            emitResult(outputStream, content);
        }
        else if (outputFormat == Cli::Commands::OutputFormat::None)
        {
            spdlog::trace("output requested not to be printed");
        }
        else
        {
            spdlog::trace("WARNING: Unrecognised outputFormat. Result discarded");
        }
    }

} // namespace Quantinuum::QuantumOrigin::Cli::Utils
