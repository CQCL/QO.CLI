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
#include <qo_common/exceptions.h>
#include <qo_common/key_response.h>
#include <qo_common/utils.h>

#include <fmt/format.h>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <numeric>

namespace Quantinuum::QuantumOrigin::Common
{

    Encrypted::Encrypted(std::vector<uint8_t> seed, uint64_t counter, std::vector<uint8_t> encryptedData, std::optional<std::vector<uint8_t>> mac)
        : seed(std::move(seed)), counter(counter), encryptedData(std::move(encryptedData)), mac(std::move(mac))
    {
    }

    Encrypted::Encrypted(const nlohmann::json &jsonObj)
    {
        seed          = decodedBase64Field(jsonObj, "seed");
        encryptedData = decodedBase64Field(jsonObj, "encrypted_data");

        if (jsonObj.contains("counter"))
        {
            counter = jsonObj["counter"].get<uint64_t>();
        }

        if (jsonObj.contains("mac"))
        {
            mac = decodedBase64Field(jsonObj, "mac");
        }
    }

    KeyResponse::KeyResponse(Encrypted encrypted, std::optional<std::vector<uint8_t>> publicKey, std::string content_type)
        : encrypted(std::move(encrypted)), publicKey(std::move(publicKey)), contentType(std::move(content_type))
    {
    }

    KeyResponse::KeyResponse(
        std::vector<uint8_t> seed, uint64_t counter, std::vector<uint8_t> encryptedData, std::optional<std::vector<uint8_t>> mac,
        std::optional<std::vector<uint8_t>> publicKey, std::string content_type)
        : KeyResponse({std::move(seed), counter, std::move(encryptedData), std::move(mac)}, std::move(publicKey), std::move(content_type))
    {
    }

    KeyResponse::KeyResponse(const nlohmann::json &jsonObj) : encrypted(jsonObj)
    {
        spdlog::trace("JSON response: {}", jsonObj.dump());

        if (jsonObj.contains("public"))
        {
            publicKey = decodedBase64Field(jsonObj, "public");
        }
        contentType = jsonObj["content_type"].get<std::string>();
    }

    KeyResponse::KeyResponse(const std::string &contentStr) : KeyResponse(nlohmann::json::parse(contentStr)) {}

    KeyResponse::KeyResponse(const std::vector<std::string> &rawContent) : KeyResponse(std::accumulate(rawContent.begin(), rawContent.end(), std::string(""))) {}

} // namespace Quantinuum::QuantumOrigin::Common
