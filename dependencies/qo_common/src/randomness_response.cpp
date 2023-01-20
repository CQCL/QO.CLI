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
#include <qo_common/randomness_response.h>

#include <fmt/format.h>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <numeric>

namespace Quantinuum::QuantumOrigin::Common
{

    RandomnessResponse::RandomnessResponse(std::vector<Encrypted> encrypted) : encrypted(std::move(encrypted)) {}

    RandomnessResponse::RandomnessResponse(std::vector<uint8_t> seed, uint64_t counter, std::vector<uint8_t> encryptedData, std::optional<std::vector<uint8_t>> mac)
        : encrypted({
              {seed, counter, encryptedData, mac}
    })
    {
    }

    RandomnessResponse::RandomnessResponse(const nlohmann::json &jsonObj)
    {
        if (jsonObj.contains("batches"))
        {
            encrypted = std::vector<Encrypted>{jsonObj["batches"].begin(), jsonObj["batches"].end()};
        }
        else
        {
            encrypted.emplace_back(jsonObj);
        }
    }

    RandomnessResponse::RandomnessResponse(const std::string &contentStr) : RandomnessResponse(nlohmann::json::parse(contentStr)) {}

    RandomnessResponse::RandomnessResponse(const std::vector<std::string> &rawContent)
        : RandomnessResponse(std::accumulate(rawContent.begin(), rawContent.end(), std::string("")))
    {
    }

} // namespace Quantinuum::QuantumOrigin::Common
