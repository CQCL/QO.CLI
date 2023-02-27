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
#pragma once

#include "qo_common/key_parameters.h"
#include "qo_common/key_response.h"
#include "qo_common/parameters.h"
#include "qo_common/request.h"

#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace Quantinuum::QuantumOrigin::Common
{

    // This class will generate a Quantum Origin key request's JSON payload ready for exporting
    class KeyRequest : public CryptoRequest
    {
      public:
        /// Constructor that sets the body of the curl request.
        /// @param keyType The key of key requested e.g AES, RSA, FALCON. For full list see API specification
        /// @param keyParameters The associated parameters for the chosen keytype. For AES this is '{"size":256}'
        /// @param nonce The nonce that will be used for the request. Format base64.
        /// @param encryptionScheme The scheme under which the returned key data should be encrypted.
        /// @param includePublic Whether the corresponding public key should be included separate in the returned data.
        KeyRequest(
            const std::string &keyType, std::string keyParameters, const std::string &nonce, EncryptionSchemeEnum encryptionScheme = EncryptionScheme::HKDF_AES_GCM,
            bool includePublic = false);

        /// Constructor that sets the body of the curl request.
        /// @param keyAndVariant The key type and variant requested e.g. RSA-256, HQC-256. For full list see API specification.
        /// @param nonce The nonce that will be used for the request. Format base64.
        /// @param encryptionScheme The scheme under which the returned key data should be encrypted.
        /// @param includePublic Whether the corresponding public key should be included separate in the returned data.
        KeyRequest(const KeyType &keyType, const std::string &nonce, EncryptionSchemeEnum encryptionScheme = EncryptionScheme::HKDF_AES_GCM, bool includePublic = false);

        /// Constructor that sets the body of the curl request.
        /// @param keyAndVariant The key type and variant requested e.g. RSA-256, HQC-256. For full list see API specification.
        /// @param nonce The nonce that will be used for the request. Format raw bytes.
        /// @param encryptionScheme The scheme under which the returned key data should be encrypted.
        /// @param includePublic Whether the corresponding public key should be included separate in the returned data.
        KeyRequest(
            const KeyType &keyType, std::vector<uint8_t> nonce, EncryptionSchemeEnum encryptionScheme = EncryptionScheme::HKDF_AES_GCM, bool includePublic = false);

        /// Constructor that sets the body of the curl request.
        /// @param keyType The key of key requested e.g AES, RSA, FALCON. For full list see API specification
        /// @param keyParameters The associated parameters for the chosen keytype. For AES this is e.g. '{"size":256}'
        /// @param nonce The nonce that will be used for the request. Format raw bytes.
        /// @param encryptionScheme The scheme under which the returned key data should be encrypted.
        /// @param includePublic Whether the corresponding public key should be included separate in the returned data.
        KeyRequest(
            KeyAlgorithmEnum keyType, std::string keyParameters, std::vector<uint8_t> nonce, EncryptionSchemeEnum encryptionScheme = EncryptionScheme::HKDF_AES_GCM,
            bool includePublic = false);

        void addRsaKeyEncryption(std::string publicKey, bool aesKeyWrap, OaepHashFunctionEnum hashFunc);

        /// Exports the class parameters as JSON. Will form the body of a key request.
        [[nodiscard]] nlohmann::json exportPayloadAsJson() const override;

        [[nodiscard]] static std::string getParameterJSON(const KeyType &keyType);

        [[nodiscard]] static std::string getAlgorithmType(const KeyType &keyType);

        using Response = KeyResponse;

      private:
        KeyAlgorithmEnum _keyAlgorithm;
        std::string _keyParameters;

        bool _includePublic = false;

        std::string _publicKey;
        bool _aesKeyWrap               = false;
        OaepHashFunctionEnum _hashFunc = OaepHashFunction::SHA_256;
    };
} // namespace Quantinuum::QuantumOrigin::Common
