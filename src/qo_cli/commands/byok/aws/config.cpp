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

namespace Quantinuum::QuantumOrigin::Cli::Commands::Byok::Aws
{

    AwsConfig::AwsConfig(const YAML::Node &cfg)
    {
        alias       = cfg["alias"].as<std::string>();
        description = cfg["description"].as<std::string>();
        expiryDate  = cfg["expiry_date"].as<std::string>();
        profile     = cfg["profile"].as<std::string>();
    }

    AwsConfig::AwsConfig(std::string alias, std::string description, std::string expiryDate, std::string profile)
        : alias(std::move(alias)), description(std::move(description)), expiryDate(std::move(expiryDate)), profile(std::move(profile))
    {
    }

    ByokAwsConfig::ByokAwsConfig(const std::string &configPath) : ByokAwsConfig(cfgFromFile(configPath)) {}

    ByokAwsConfig::ByokAwsConfig(const YAML::Node &cfg) : awsConfig(cfg["aws"] ? cfg["aws"] : YAML::Node()) {}

    ByokAwsConfig::ByokAwsConfig(AwsConfig awsConfig) : awsConfig(std::move(awsConfig)) {}

} // namespace Quantinuum::QuantumOrigin::Cli::Commands::Byok::Aws
