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

namespace Quantinuum::QuantumOrigin::Cli::Commands::Byok::Az
{

    AzConfig::AzConfig(const YAML::Node &cfg)
    {
        if (cfg["kid"])
        {
            kId = cfg["kid"].as<std::string>();
        }
        if (cfg["pem_file"])
        {
            pemFileName = cfg["pem_file"].as<std::string>();
        }
    }

    AzConfig::AzConfig(std::string kId, std::string pemFileName) : kId(std::move(kId)), pemFileName(std::move(pemFileName)) {}

    ByokAzConfig::ByokAzConfig(const std::string &configPath) : ByokAzConfig(cfgFromFile(configPath)) {}

    ByokAzConfig::ByokAzConfig(const YAML::Node &cfg)
        : azConfig(cfg["az"] ? cfg["az"] : YAML::Node()), keyParametersConfig(cfg["key_parameters"] ? cfg["key_parameters"] : YAML::Node()),
          generalConfig(cfg["general"] ? cfg["general"] : YAML::Node())
    {
    }

    ByokAzConfig::ByokAzConfig(KeyParametersConfig keyParametersConfig, AzConfig azConfig, GeneralConfig generalConfig)
        : azConfig(std::move(azConfig)), keyParametersConfig(std::move(keyParametersConfig)), generalConfig(std::move(generalConfig))
    {
    }

} // namespace Quantinuum::QuantumOrigin::Cli::Commands::Byok::Az
