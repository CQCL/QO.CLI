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

namespace Quantinuum::QuantumOrigin::Cli::Commands::Byok::Aws
{

    class AwsConfig
    {
      public:
        explicit AwsConfig(const YAML::Node &cfg);
        AwsConfig() = default;
        explicit AwsConfig(std::string alias, std::string description, std::string expiryDate, std::string profile = "default");

        [[nodiscard]] const std::string &getAlias() const
        {
            return alias;
        }

        [[nodiscard]] const std::string &getDescription() const
        {
            return description;
        }

        [[nodiscard]] const std::string &getExpiryDate() const
        {
            return expiryDate;
        }

        [[nodiscard]] const std::string &getProfile() const
        {
            return profile;
        }

      private:
        std::string alias;
        std::string description;
        std::string expiryDate;
        std::string profile;
    };

    class ByokAwsConfig
    {
      public:
        explicit ByokAwsConfig(const std::string &configPath);
        explicit ByokAwsConfig(const YAML::Node &cfg);
        explicit ByokAwsConfig(AwsConfig awsConfig);

        [[nodiscard]] const AwsConfig &getAwsConfig() const
        {
            return awsConfig;
        }

      private:
        AwsConfig awsConfig;
    };

} // namespace Quantinuum::QuantumOrigin::Cli::Commands::Byok::Aws
