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
#include <qo_common/usage_response.h>

#include <fmt/format.h>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

using nlohmann::json;

namespace Quantinuum::QuantumOrigin::Common
{
    UsageResponse::UsageResponse(const std::vector<std::string> &rawContent)
    {
        contentStr = std::accumulate(rawContent.begin(), rawContent.end(), std::string(""));
        if (contentStr.empty())
        {
            throw ApiError("Usage response is empty. Expecting a json payload.");
        }

        auto jsonObj = json::parse(contentStr);
        spdlog::trace("JSON response: {}", jsonObj.dump());
    }
} // namespace Quantinuum::QuantumOrigin::Common
