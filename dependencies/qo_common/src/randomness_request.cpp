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
#include "qo_common/randomness_request.h"

#include <cppcodec/base64_rfc4648.hpp>

namespace Quantinuum::QuantumOrigin::Common
{

    RandomnessRequest::RandomnessRequest(uint32_t size, std::vector<uint8_t> nonce, EncryptionSchemeEnum encryptionScheme)
        : CryptoRequest("randomness", std::move(nonce), encryptionScheme), _size(size)
    {
    }

    RandomnessRequest::RandomnessRequest(uint32_t size, std::vector<std::vector<uint8_t>> nonces, EncryptionSchemeEnum encryptionScheme)
        : CryptoRequest("randomness", std::move(nonces), encryptionScheme), _size(size)
    {
    }

    nlohmann::json RandomnessRequest::exportPayloadAsJson() const
    {
        nlohmann::json jsonRequestPayload;

        if (_nonces.size() == 1)
        {
            jsonRequestPayload["nonce"] = cppcodec::base64_rfc4648::encode(_nonces[0]);
        }
        else
        {

            jsonRequestPayload["nonces"] = nlohmann::json::array();

            for (const auto &nonce : _nonces)
            {
                jsonRequestPayload["nonces"].emplace_back(cppcodec::base64_rfc4648::encode(nonce));
            }
        }

        jsonRequestPayload["size"]              = _size;
        jsonRequestPayload["encryption_scheme"] = std::string(_encryptionScheme);

        return jsonRequestPayload;
    }

} // namespace Quantinuum::QuantumOrigin::Common
