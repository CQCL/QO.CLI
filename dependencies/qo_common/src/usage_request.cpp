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

#include "qo_common/parameters.h"
#include "qo_common/request.h"
#include <fmt/format.h>
#include <qo_common/usage_request.h>

namespace Quantinuum::QuantumOrigin::Common
{
    UsageRequest::UsageRequest(std::string from, std::string to, std::string groupBy)
        : Request("usage", httpMethod::GET), _from(std::move(from)), _to(std::move(to)), _groupBy(std::move(groupBy))
    {
    }

    UsageRequest::UsageRequest(std::string from, std::string to, UsageQueryEnum groupBy)
        : Request("usage", httpMethod::GET), _from(std::move(from)), _to(std::move(to)), _groupBy(std::move(groupBy))
    {
    }

    std::string UsageRequest::exportQuery() const
    {
        return fmt::format("group_by={}&from={}&to={}", std::string(_groupBy), _from, _to);
    }

    nlohmann::json UsageRequest::exportPayloadAsJson() const
    {
        return nlohmann::json();
    }

} // namespace Quantinuum::QuantumOrigin::Common
