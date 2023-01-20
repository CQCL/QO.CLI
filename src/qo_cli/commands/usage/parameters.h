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

#include "parameter_base.h"
#include <api_parameters.h>

#include <optional>
#include <string>

namespace Quantinuum::QuantumOrigin::Cli::Commands::Usage
{

    extern const std::unordered_map<std::string, Common::UsageQuery> usageQueryMap;

    class UsageParameters : public IParameters
    {
      public:
        std::string from;
        std::string to;
        Common::UsageQuery groupBy;
        ApiParameters apiParameters;

        OutputParameters outputParameters;

        void print() const override;
    };

} // namespace Quantinuum::QuantumOrigin::Cli::Commands::Usage
