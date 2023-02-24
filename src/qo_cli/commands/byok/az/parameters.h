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

#include "byok/parameters.h"
#include "parameter_base.h"

namespace Quantinuum::QuantumOrigin::Cli::Commands::Byok::Az
{

    class KeyParameters
    {
      public:
        std::string json; // TODO: Use keytype-specific parameters instead of raw JSON
    };

    class ByokAzParameters : public IParameters
    {
      public:
        explicit ByokAzParameters(const ByokParameters &byokParams);

        // ApiParameters + DecryptionParameters
        const ByokParameters &byokParams;
        std::optional<Common::KeyAlgorithm> keyAlgorithm;
        KeyParameters keyParameters;

        OutputParameters outputParameters;

        std::string pemFileName;
        std::string kId;

        void print() const override;
    };

} // namespace Quantinuum::QuantumOrigin::Cli::Commands::Byok::Az
