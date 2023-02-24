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
#include "decrypt.h"
#include "key_writer.h"

#include <qo_decrypt/qo_asn1_decode.h>
#include <qo_decrypt/qo_asn1_encode.h>
#include <qo_decrypt/qo_cleanse.h>
#include <qo_decrypt/qo_crypto.h>

#include <algorithm>
#include <cstring>
#include <optional>
#include <ostream>
#include <string>
#include <utility>

namespace Quantinuum::QuantumOrigin::Cli::Commands
{

    namespace
    {
        void encode_ecx_25519(std::vector<uint8_t> &encoded)
        {
            uint8_t *ecxPublicKey  = nullptr;
            size_t ecxPublicSize   = 0;
            uint8_t *ecxPrivateKey = nullptr;
            size_t ecxPrivateSize  = 0;

            // incoming payload contains pubkey + privkey in ASN1 form, we first get the actual keys out of this encoded form
            int rv = qo_asn1_decode_ecx(encoded.data(), encoded.size(), &ecxPublicKey, &ecxPublicSize, &ecxPrivateKey, &ecxPrivateSize);

            if (rv != ASN1_DECODE_SUCCESS)
            {
                if (ecxPrivateKey)
                {
                    free(ecxPrivateKey);
                }
                if (ecxPublicKey)
                {
                    free(ecxPublicKey);
                }
                auto msg = "Failed to decode ecx key content.";
                spdlog::error(msg);
                throw std::runtime_error(msg);
            }
            free(ecxPublicKey); // we will discard the public key, only encoding the private key.

            // we then encode the private key so that openssl can use it to derive a public key, back into ASN1 form (PKCS8 private key form)
            uint8_t *encodedPrivateKey = nullptr;
            int encodedLength          = qo_asn1_encode_ecx_25519(&encodedPrivateKey, ecxPrivateKey, ecxPrivateSize);
            if (encodedLength <= 0)
            {
                // Throw an exception if encodedLength is zero or negative, which is an error condition
                free(ecxPrivateKey);
                auto msg = "Failed to encode the ecx 25519 key";
                spdlog::error(msg);
                throw std::runtime_error(msg);
            }

            // positive encodedLength is a success, we overwrite the given content with the encoded private key.
            encoded.assign(encodedPrivateKey, encodedPrivateKey + encodedLength); // assign() resizes and replaces content
            // cleanup remaining allocations prior to exit
            free(encodedPrivateKey);
            free(ecxPrivateKey);
        }
    } // namespace

    CliDecrypt::CliDecrypt(const std::vector<uint8_t> &sharedSecret, const std::vector<uint8_t> &nonce, const Quantinuum::QuantumOrigin::Common::KeyResponse &keyResponse)
        : _sharedSecret(sharedSecret.begin(), sharedSecret.end()), _nonce(nonce.begin(), nonce.end()), _seed(keyResponse.encrypted.seed),
          _counter(keyResponse.encrypted.counter), _encryptedData(keyResponse.encrypted.encryptedData),
          _keyType(Common::parseKeyTypeAndVariantString(keyResponse.contentType))
    {
    }

    CliDecrypt::CliDecrypt(
        const std::vector<uint8_t> &sharedSecret, const std::vector<uint8_t> &nonce, std::vector<uint8_t> seed, uint64_t counter, std::vector<uint8_t> encryptedData,
        std::optional<Common::KeyType> keyTypeAndVariant)
        : _sharedSecret(sharedSecret.begin(), sharedSecret.end()), _nonce(nonce.begin(), nonce.end()), _seed(std::move(seed)), _counter(counter),
          _encryptedData(std::move(encryptedData)), _keyType(std::move(keyTypeAndVariant))
    {
    }

    CliDecrypt::~CliDecrypt()
    {
        CleanseStdVector(_sharedSecret);
        CleanseStdVector(_pPlainTextOut);
    }

    void CliDecrypt::init()
    {
        spdlog::debug("DEBUG: Decoded payload len = {}", _encryptedData.size());
        // The encryptedNewKey param contains the encrypted key + a 16 byte tag
        // and GCM produces as much data out as you put in.
        // So, in theory, we only need storage for the entire encrypted_data, less 16
        if (_encryptedData.size() < (PAYLOAD_DATA_MINIMUM_LEN + PAYLOAD_TAG_LEN))
        {
            // The supplied value for newkey is too short to contain both the newkey and the 16 byte GCM tag
            const std::string errMsg = "ERROR: The supplied value for \"encryptedkey\" (" + std::to_string(_encryptedData.size()) + " bytes) is too short";
            spdlog::trace(errMsg.c_str());
            throw std::runtime_error("ERROR: The supplied value for \"encryptedkey\" (" + std::to_string(_encryptedData.size()) + " bytes) is too short");
        }

        size_t cbPlainTextOut = (size_t)(_encryptedData.size() - PAYLOAD_TAG_LEN);
        _pPlainTextOut        = std::vector<uint8_t>(cbPlainTextOut);

        spdlog::trace("DEBUG: cbPlainTextOut = {}", _pPlainTextOut.size());
    }

    void CliDecrypt::decryptAesGcm()
    {
        spdlog::trace("DEBUG: cbPlainTextOut = {}", _pPlainTextOut.size());
        size_t plainTextBytesWritten = 0;

        spdlog::trace("Decrypting");
        int rc = qo_decrypt_aes_gcm(
            _sharedSecret.data(), _sharedSecret.size(),   // 32
            _encryptedData.data(), _encryptedData.size(), // >= 16
            _seed.data(), _seed.size(),                   // 36
            _counter,                                     // counter typically starts at 0
            _nonce.data(), _nonce.size(),                 // authenticated_data
            _pPlainTextOut.data(), _pPlainTextOut.size(), // >= cipher_len - 16
            &plainTextBytesWritten);
        if (rc != 0)
        {
            std::string err = qo_decrypt_error_description(rc);
            spdlog::error("Decrypt failed with return code {}: {}", rc, err);
            throw std::runtime_error("Decrypt failed with return code " + std::to_string(rc) + ": " + err);
        }
        _pPlainTextOut.resize(plainTextBytesWritten);

        if (_keyType == Common::KeyType{Common::Cli_Alg_Type::KEY_TYPE_EC, Common::Cli_EC_Variant::X25519})
        {
            spdlog::debug("Response contains a content type that matched EC-X25519, encode it's private key part differently");
            encode_ecx_25519(_pPlainTextOut);
        }
    }

    void CliDecrypt::runDecrypt(std::optional<Cli::Commands::OutputFormat> outputFormat, std::ostream &outputStream)
    {
        init();
        decryptAesGcm();

        // Set default output format based on key type
        if (!outputFormat)
        {
            outputFormat = defaultOutputFormat(_keyType);
        }

        Utils::KeyWriter keyWriter(_keyType);
        keyWriter.outputKeyData(_pPlainTextOut, *outputFormat, outputStream);
    }

    const std::vector<uint8_t> &CliDecrypt::getResult() const
    {
        return _pPlainTextOut;
    }

} // namespace Quantinuum::QuantumOrigin::Cli::Commands
