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

#include "qo_common/parameters.h"

#include <nlohmann/json.hpp>

#include <string>

namespace Quantinuum::QuantumOrigin::Common
{

    using nlohmann::json;

    enum httpMethod
    {
        GET,
        POST
    };

    class Request
    {
      public:
        /// Constructor that sets the endpoint of the curl request.
        /// @param endpoint The API endpoint that will be used for the request.
        explicit Request(std::string endpoint, httpMethod method);

        /// Exports the class parameters as JSON. Will form the body of a key request.
        [[nodiscard]] virtual nlohmann::json exportPayloadAsJson() const = 0;
        [[nodiscard]] virtual std::string exportQuery() const            = 0;

        /// Get the endpoint URL
        [[nodiscard]] const std::string &getEndpoint() const;
        [[nodiscard]] const httpMethod &getMethod() const;

      protected:
        std::string _endpoint;
        httpMethod _method;
    };

    class CryptoRequest : public Request
    {
      public:
        CryptoRequest(std::string endpoint, std::vector<uint8_t> nonce, EncryptionSchemeEnum encryptionScheme = EncryptionScheme::HKDF_AES_GCM);
        CryptoRequest(std::string endpoint, std::vector<std::vector<uint8_t>> nonces, EncryptionSchemeEnum encryptionScheme = EncryptionScheme::HKDF_AES_GCM);

        [[nodiscard]] std::string exportQuery() const override
        {
            return "";
        }

      protected:
        std::vector<std::vector<uint8_t>> _nonces;
        EncryptionSchemeEnum _encryptionScheme;
    };
} // namespace Quantinuum::QuantumOrigin::Common
