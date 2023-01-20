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

#include "key_parameters.h"
#include "parameter_base.h"
#include <decryption_parameters.h>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace Quantinuum::QuantumOrigin::Cli::Commands::Decrypt
{

    class DecryptParameters : public IParameters
    {
      public:
        std::string inputFilename;

        DecryptionParameters decryptionParameters;

        uint64_t counter = 0;
        std::vector<uint8_t> seed;
        std::vector<uint8_t> encryptedNewKey;
        std::optional<KeyTypeAndVariant> keyTypeAndVariant;

        OutputParameters outputParameters;

        void print() const override;
    };

} // namespace Quantinuum::QuantumOrigin::Cli::Commands::Decrypt
