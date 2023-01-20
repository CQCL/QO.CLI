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

#include "qo_common/onboard_response.h"
#include "qo_common/request.h"

#include <nlohmann/json.hpp>

#include <string>
#include <vector>

namespace Quantinuum::QuantumOrigin::Common
{
    class OnboardRequest : public Request
    {
      public:
        /// Constructor for the body of the curl request.
        /// @param publicKey the ephemeral public key the server will use for ECIES.
        explicit OnboardRequest(std::string publicKey);

        [[nodiscard]] nlohmann::json exportPayloadAsJson() const override;
        [[nodiscard]] std::string exportQuery() const override
        {
            return "";
        };

        using Response = OnboardResponse;

      private:
        std::string _publicKey;
    };
} // namespace Quantinuum::QuantumOrigin::Common
