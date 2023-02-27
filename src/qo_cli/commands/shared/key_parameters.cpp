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
#include "key_parameters.h"

namespace Quantinuum::QuantumOrigin::Cli
{

    Commands::OutputFormat defaultOutputFormat(const std::optional<Common::KeyType> &keyType)
    {
        if (keyType)
        {
            if (keyType->algorithm == Common::Cli_Alg_Type::KEY_TYPE_RSA || keyType->algorithm == Common::Cli_Alg_Type::KEY_TYPE_EC)
            {
                return Cli::Commands::OutputFormat::Pem;
            }
            else if (keyType->algorithm == Common::Cli_Alg_Type::KEY_TYPE_AES || keyType->algorithm == Common::Cli_Alg_Type::KEY_TYPE_RAND)
            {
                return Cli::Commands::OutputFormat::Base64;
            }
        }

        return Cli::Commands::OutputFormat::Jwk;
    }

} // namespace Quantinuum::QuantumOrigin::Cli
