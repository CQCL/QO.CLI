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
#include "shared_config.h"
#include "api_parameters.h"
#include "command_base.hpp"

#include <boost/algorithm/string.hpp>
#include <spdlog/spdlog.h>
#include <yaml-cpp/yaml.h>

namespace Quantinuum::QuantumOrigin::Cli
{

    YAML::Node cfgFromFile(const std::string &configPath)
    {
        spdlog::info("Reading config from: {}", configPath);

        try
        {
            return YAML::LoadFile(configPath);
        }
        catch (const YAML::Exception &ex)
        {
            throw ConfigYamlError(configPath, ex);
        }
    }

    ConfigError::ConfigError(std::string filename, const std::string &msg)
        : std::runtime_error(fmt::format("Failed to parse config file at '{}': {}", filename, msg)), filename(std::move(filename))
    {
    }

    ConfigYamlError::ConfigYamlError(std::string filename, const YAML::Exception &ex)
        : ConfigError(std::move(filename), fmt::format("line {}, column {}: {}", ex.mark.line, ex.mark.column, ex.msg)), ex(ex)
    {
    }

    KeyParametersConfig::KeyParametersConfig(
        const std::string &nonceFormatString, const std::string &nonceString, std::string keyParameters, std::optional<Common::KeyAlgorithm> keyAlgorithm,
        const std::string &sharedSecretFormatString, const std::string &sharedSecretString)
        : keyParameters(std::move(keyParameters)), keyAlgorithm(keyAlgorithm)
    {
        Commands::DataFormat nonceFormat = Commands::DataFormat::Base64;
        if (!nonceFormatString.empty())
        {
            auto found = Commands::dataFormatMap.find(nonceFormatString);
            if (found != Commands::dataFormatMap.end())
            {
                nonceFormat = found->second;
            }
        }

        if (!nonceString.empty())
        {
            Commands::DataParameter nonceData(nonceString, nonceFormat);
            nonce = nonceData.getData();
        }

        Commands::DataFormat sharedSecretFormat = Commands::DataFormat::Base64;
        if (!sharedSecretFormatString.empty())
        {
            auto found = Commands::dataFormatMap.find(sharedSecretFormatString);
            if (found != Commands::dataFormatMap.end())
            {
                sharedSecretFormat = found->second;
            }
        }

        if (!sharedSecretString.empty())
        {
            Commands::DataParameter sharedSecretData(sharedSecretString, sharedSecretFormat);
            sharedSecret = sharedSecretData.getData();
        }
    }

    KeyParametersConfig::KeyParametersConfig(
        std::vector<uint8_t> nonce, std::string keyParameters, std::optional<Common::KeyAlgorithm> keyAlgorithm, std::vector<uint8_t> sharedSecret)
        : nonce(std::move(nonce)), keyParameters(std::move(keyParameters)), keyAlgorithm(keyAlgorithm), sharedSecret(std::move(sharedSecret))
    {
    }

    KeyParametersConfig::KeyParametersConfig(const YAML::Node &cfg)
    {
        Commands::DataFormat nonceFormat = Commands::DataFormat::Base64;
        if (cfg["nonce_format"])
        {
            auto nonceFormatString = cfg["nonce_format"].as<std::string>();

            auto found = Commands::dataFormatMap.find(nonceFormatString);
            if (found != Commands::dataFormatMap.end())
            {
                nonceFormat = found->second;
            }
        }
        if (cfg["nonce"])
        {
            auto nonceString = cfg["nonce"].as<std::string>();

            if (!nonceString.empty())
            {
                Commands::DataParameter nonceData(nonceString, nonceFormat);
                nonce = nonceData.getData();
            }
        }

        if (cfg["key_parameters"])
        {
            keyParameters = cfg["key_parameters"].as<std::string>();
        }

        if (cfg["key_type"])
        {
            auto keyTypeString = cfg["key_type"].as<std::string>();
            keyType            = Common::parseKeyTypeAndVariantString(keyTypeString);
        }

        if (cfg["key_algorithm"])
        {
            auto keyAlgorithmString = cfg["key_algorithm"].as<std::string>();

            auto found = Commands::keyAlgorithmMap.find(keyAlgorithmString);
            if (found != Commands::keyAlgorithmMap.end())
            {
                keyAlgorithm = found->second;
            }
            else
            {
                localKeyType = Common::parseKeyTypeAndVariantString(keyAlgorithmString);
            }
        }

        Commands::DataFormat sharedSecretFormat = Commands::DataFormat::Base64;
        if (cfg["shared_secret_format"])
        {
            auto sharedSecretFormatString = cfg["shared_secret_format"].as<std::string>();

            auto found = Commands::dataFormatMap.find(sharedSecretFormatString);
            if (found != Commands::dataFormatMap.end())
            {
                sharedSecretFormat = found->second;
            }
        }
        if (cfg["shared_secret"])
        {
            auto sharedSecretString = cfg["shared_secret"].as<std::string>();

            if (!sharedSecretString.empty())
            {
                Commands::DataParameter sharedSecretData(sharedSecretString, sharedSecretFormat);
                sharedSecret = sharedSecretData.getData();
            }
        }
    }

    CredentialsConfig::CredentialsConfig(const YAML::Node &cfg)
    {
        if (cfg["certificate"])
        {
            certificatePath = cfg["certificate"].as<std::string>();
            privateKeyPath  = cfg["private_key"].as<std::string>();
        }

        if (cfg["api_key"])
        {
            apiKey = cfg["api_key"].as<std::string>();
        }

        if (cfg["url"])
        {
            url = cfg["url"].as<std::string>();
        }

        if (cfg["client_id"])
        {
            clientId = cfg["client_id"].as<std::string>();
        }
    }

    CredentialsConfig::CredentialsConfig(std::string certificatePath, std::string privateKeyPath, std::string url, std::string clientId, std::string apiKey)
        : certificatePath(std::move(certificatePath)), privateKeyPath(std::move(privateKeyPath)), url(std::move(url)), clientId(std::move(clientId)),
          apiKey(std::move(apiKey))
    {
    }

    GeneralConfig::GeneralConfig(
        std::string onboardingAuth, std::string outputFilename, spdlog::level::level_enum logLevel, std::optional<Cli::Commands::OutputFormat> outputFormat)
        : onboardingAuth(std::move(onboardingAuth)), outputFormat(outputFormat), outputFilename(std::move(outputFilename)), logLevel(logLevel)
    {
    }

    GeneralConfig::GeneralConfig(const YAML::Node &cfg) : logLevel(spdlog::level::level_enum::info)
    {
        if (cfg["onboarding_auth"])
        {
            onboardingAuth = cfg["onboarding_auth"].as<std::string>();
        }

        if (cfg["output_format"])
        {
            auto outputFormatString = cfg["output_format"].as<std::string>();

            auto found = Cli::Commands::outputFormatMap.find(outputFormatString);
            if (found != Cli::Commands::outputFormatMap.end())
            {
                outputFormat = found->second;
            }
        }

        if (cfg["output_filename"])
        {
            outputFilename = cfg["output_filename"].as<std::string>();
        }

        if (cfg["logging"])
        {
            auto logLevelString = cfg["logging"].as<std::string>();

            if (boost::iequals(logLevelString, "TRACE"))
            {
                logLevel = spdlog::level::level_enum::trace;
            }
            else if (boost::iequals(logLevelString, "DEBUG"))
            {
                logLevel = spdlog::level::level_enum::debug;
            }
            else if (boost::iequals(logLevelString, "INFO"))
            {
                logLevel = spdlog::level::level_enum::info;
            }
            else if (boost::iequals(logLevelString, "WARN") || boost::iequals(logLevelString, "WARNING"))
            {
                logLevel = spdlog::level::level_enum::warn;
            }
            else if (boost::iequals(logLevelString, "ERR") || boost::iequals(logLevelString, "ERROR"))
            {
                logLevel = spdlog::level::level_enum::err;
            }
            else if (boost::iequals(logLevelString, "CRITICAL"))
            {
                logLevel = spdlog::level::level_enum::critical;
            }
            else if (boost::iequals(logLevelString, "OFF") || boost::iequals(logLevelString, "NONE"))
            {
                logLevel = spdlog::level::level_enum::off;
            }
        }
    }



} // namespace Quantinuum::QuantumOrigin::Cli
