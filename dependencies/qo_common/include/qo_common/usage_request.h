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
#include "qo_common/request.h"
#include "qo_common/usage_response.h"

#include <nlohmann/json.hpp>

#include <string>
#include <vector>

namespace Quantinuum::QuantumOrigin::Common
{
    class UsageRequest : public Request
    {
      public:
        UsageRequest(std::string from, std::string to, std::string groupBy);
        /// Constructor for the body of the curl request.
        UsageRequest(std::string from, std::string to, UsageQueryEnum groupBy);

        /// Exports the class parameters as JSON. Will form the body of a key request.
        [[nodiscard]] std::string exportQuery() const override;
        [[nodiscard]] nlohmann::json exportPayloadAsJson() const override;

        using Response = UsageResponse;

      private:
        UsageQueryEnum _groupBy;
        std::string _from;
        std::string _to;
    };
} // namespace Quantinuum::QuantumOrigin::Common
