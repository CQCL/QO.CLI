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

#include <nlohmann/json.hpp>

#include <optional>
#include <string>
#include <vector>

// This class parse the API response that is written to rawContent into the parts needed for decryption.

namespace Quantinuum::QuantumOrigin::Common
{
    class Encrypted
    {
      public:
        Encrypted(std::vector<uint8_t> seed, uint64_t counter, std::vector<uint8_t> encryptedData, std::optional<std::vector<uint8_t>> mac = std::nullopt);
        explicit Encrypted(const nlohmann::json &jsonObj);

        std::vector<uint8_t> seed;
        uint64_t counter = 0;
        std::vector<uint8_t> encryptedData;
        std::optional<std::vector<uint8_t>> mac;
    };

    class KeyResponse
    {
      public:
        explicit KeyResponse(Encrypted encrypted, std::optional<std::vector<uint8_t>> publicKey = std::nullopt, std::string content_type = "");
        KeyResponse(
            std::vector<uint8_t> seed, uint64_t counter, std::vector<uint8_t> encryptedData, std::optional<std::vector<uint8_t>> mac = std::nullopt,
            std::optional<std::vector<uint8_t>> publicKey = std::nullopt, std::string content_type = "");
        explicit KeyResponse(const nlohmann::json &jsonObj);
        explicit KeyResponse(const std::string &contentStr);
        explicit KeyResponse(const std::vector<std::string> &rawContent);

        Encrypted encrypted;
        std::optional<std::vector<uint8_t>> publicKey;
        std::string contentType;
    };
} // namespace Quantinuum::QuantumOrigin::Common
