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

#include <shared_config.h>

#include <yaml-cpp/yaml.h>

namespace Quantinuum::QuantumOrigin::Cli::Commands::Byok::Az
{

    class AzConfig
    {
      public:
        explicit AzConfig(const YAML::Node &cfg);
        AzConfig() = default;
        explicit AzConfig(std::string kId, std::string pemFileName);

        [[nodiscard]] const std::string &getKid() const
        {
            return kId;
        }

        [[nodiscard]] const std::string &getPemFileName() const
        {
            return pemFileName;
        }

      private:
        std::string kId;
        std::string pemFileName;
    };

    class ByokAzConfig
    {
      public:
        explicit ByokAzConfig(const std::string &configPath);
        explicit ByokAzConfig(const YAML::Node &cfg);
        explicit ByokAzConfig(KeyParametersConfig keyParametersConfig, AzConfig azConfig, GeneralConfig generalConfig);

        [[nodiscard]] const AzConfig &getAzConfig() const
        {
            return azConfig;
        }

        [[nodiscard]] const KeyParametersConfig &getKeyParametersConfig() const
        {
            return keyParametersConfig;
        }

        [[nodiscard]] const GeneralConfig &getGeneralConfig() const
        {
            return generalConfig;
        }

      private:
        AzConfig azConfig;
        KeyParametersConfig keyParametersConfig;
        GeneralConfig generalConfig;
    };

} // namespace Quantinuum::QuantumOrigin::Cli::Commands::Byok::Az
