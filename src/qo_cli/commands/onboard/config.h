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

namespace Quantinuum::QuantumOrigin::Cli::Commands::Onboard
{

    class OnboardConfig
    {
      public:
        explicit OnboardConfig(const std::string &configPath);
        explicit OnboardConfig(const YAML::Node &cfg);
        OnboardConfig(CredentialsConfig credentialsConfig);

        [[nodiscard]] const CredentialsConfig &getCredentialsConfig() const
        {
            return credentialsConfig;
        }

      private:
        CredentialsConfig credentialsConfig;
    };

} // namespace Quantinuum::QuantumOrigin::Cli::Commands::Onboard
