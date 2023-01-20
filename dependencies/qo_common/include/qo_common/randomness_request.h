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

#include "qo_common/key_response.h"
#include "qo_common/parameters.h"
#include "qo_common/randomness_response.h"
#include "qo_common/request.h"

namespace Quantinuum::QuantumOrigin::Common
{

    class RandomnessRequest : public CryptoRequest
    {
      public:
        RandomnessRequest(uint32_t size, std::vector<uint8_t> nonce, EncryptionSchemeEnum encryptionScheme = EncryptionScheme::HKDF_AES_GCM);
        RandomnessRequest(uint32_t size, std::vector<std::vector<uint8_t>> nonces, EncryptionSchemeEnum encryptionScheme = EncryptionScheme::HKDF_AES_GCM);

        /// Exports the class parameters as JSON. Will form the body of a key request.
        [[nodiscard]] nlohmann::json exportPayloadAsJson() const override;

        using Response = RandomnessResponse;

        // Currently the server enforces a maximum request size of 2MB (2 x 1024 x 1024 bytes).
        static const size_t MAX_BYTES_PER_REQUEST = 2097152;

      private:
        uint32_t _size;
    };

} // namespace Quantinuum::QuantumOrigin::Common
