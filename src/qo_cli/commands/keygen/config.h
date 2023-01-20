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

namespace Quantinuum::QuantumOrigin::Cli::Commands::Keygen
{

    class KeygenConfig
    {
      public:
        explicit KeygenConfig(const std::string &configPath);
        explicit KeygenConfig(const YAML::Node &cfg);
        KeygenConfig(KeyParametersConfig keyParametersConfig, CredentialsConfig credentialsConfig, GeneralConfig generalConfig);

        [[nodiscard]] const KeyParametersConfig &getKeyParametersConfig() const
        {
            return keyParametersConfig;
        }

        [[nodiscard]] const CredentialsConfig &getCredentialsConfig() const
        {
            return credentialsConfig;
        }

        [[nodiscard]] const GeneralConfig &getGeneralConfig() const
        {
            return generalConfig;
        }

      private:
        KeyParametersConfig keyParametersConfig;
        CredentialsConfig credentialsConfig;
        GeneralConfig generalConfig;
    };

} // namespace Quantinuum::QuantumOrigin::Cli::Commands::Keygen
