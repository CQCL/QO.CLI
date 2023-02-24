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
#include "qo_common/key_request.h"
#include "qo_common/exceptions.h"
#include "qo_common/parameters.h"

#include <cppcodec/base64_rfc4648.hpp>

#include <string>

namespace Quantinuum::QuantumOrigin::Common
{
    KeyRequest::KeyRequest(const std::string &keyType, std::string keyParameters, const std::string &nonce, EncryptionSchemeEnum encryptionScheme, bool includePublic)
        : KeyRequest(keyType, std::move(keyParameters), cppcodec::base64_rfc4648::decode(nonce), encryptionScheme, includePublic)
    {
    }

    KeyRequest::KeyRequest(const KeyType &keyType, const std::string &nonce, EncryptionSchemeEnum encryptionScheme, bool includePublic)
        : KeyRequest(keyType, cppcodec::base64_rfc4648::decode(nonce), encryptionScheme, includePublic)
    {
    }

    KeyRequest::KeyRequest(const KeyType &keyType, std::vector<uint8_t> nonce, EncryptionSchemeEnum encryptionScheme, bool includePublic)
        : CryptoRequest("keygen", std::move(nonce), encryptionScheme), _keyAlgorithm(this->getAlgorithmType(keyType)),
          _keyParameters(std::move(this->getParameterJSON(keyType))), _includePublic(includePublic)
    {
    }

    KeyRequest::KeyRequest(
        KeyAlgorithmEnum keyAlgorithm, std::string keyParameters, std::vector<uint8_t> nonce, EncryptionSchemeEnum encryptionScheme, bool includePublic)
        : CryptoRequest("keygen", std::move(nonce), encryptionScheme), _keyAlgorithm(keyAlgorithm), _keyParameters(std::move(keyParameters)),
          _includePublic(includePublic)
    {
    }

    void KeyRequest::addRsaKeyEncryption(std::string publicKey, bool aesKeyWrap, OaepHashFunctionEnum hashFunc)
    {
        _publicKey  = publicKey;
        _aesKeyWrap = aesKeyWrap;
        _hashFunc   = hashFunc;
    }

    nlohmann::json KeyRequest::exportPayloadAsJson() const
    {
        nlohmann::json jsonRequestPayload;
        jsonRequestPayload["key_type"] = std::string(_keyAlgorithm);

        jsonRequestPayload["key_parameters"] = nlohmann::json::parse(_keyParameters);

        if (_nonces.size() == 1)
        {
            jsonRequestPayload["nonce"] = cppcodec::base64_rfc4648::encode(_nonces[0]);
        }
        else
        {
            throw ApiError("Batching of key generation requests not yet supported");
        }

        jsonRequestPayload["include_public"] = _includePublic;

        jsonRequestPayload["encryption_scheme"] = std::string(_encryptionScheme);

        if (!_publicKey.empty())
        {
            jsonRequestPayload["public_key"]         = _publicKey;
            jsonRequestPayload["aes_key_wrap"]       = _aesKeyWrap;
            jsonRequestPayload["oaep_hash_function"] = _hashFunc;
        }

        return jsonRequestPayload;
    }

    std::string KeyRequest::getParameterJSON(const KeyType &keyType)
    {
        nlohmann::json jsonRequest;
        auto getVariant = [](const KeyType &keyType) { return std::get<1>(typeVariantNames.at(keyType.variant)); };
        if (Cli_Alg_Type::KEY_TYPE_AES == keyType.algorithm || Cli_Alg_Type::KEY_TYPE_RSA == keyType.algorithm)
        {
            jsonRequest["size"] = std::get<int>(getVariant(keyType));
        }
        else if (keyType.algorithm == Cli_Alg_Type::KEY_TYPE_EC)
        {
            jsonRequest["curve"] = std::get<std::string>(getVariant(keyType));
        }
        else
        {
            jsonRequest["variant"] = std::get<std::string>(getVariant(keyType));
        }
        return jsonRequest.dump();
    }

    std::string KeyRequest::getAlgorithmType(const KeyType &keyType)
    {
        return std::get<0>(typeVariantNames.at(keyType.variant));
    }
} // namespace Quantinuum::QuantumOrigin::Common
