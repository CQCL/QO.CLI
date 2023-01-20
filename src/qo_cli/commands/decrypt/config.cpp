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
#include "config.h"

namespace Quantinuum::QuantumOrigin::Cli::Commands::Decrypt
{

    DecryptConfig::DecryptConfig(const std::string &configPath) : DecryptConfig(cfgFromFile(configPath)) {}

    DecryptConfig::DecryptConfig(const YAML::Node &cfg)
        : keyParametersConfig(cfg["key_parameters"] ? cfg["key_parameters"] : YAML::Node()), generalConfig(cfg["general"] ? cfg["general"] : YAML::Node())
    {
    }

    DecryptConfig::DecryptConfig(KeyParametersConfig keyParametersConfig, GeneralConfig generalConfig)
        : keyParametersConfig(std::move(keyParametersConfig)), generalConfig(std::move(generalConfig))
    {
    }

} // namespace Quantinuum::QuantumOrigin::Cli::Commands::Decrypt
