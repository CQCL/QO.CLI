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

#include <qo_common/parameters.h>

#include <spdlog/spdlog.h>
#include <yaml-cpp/yaml.h>

#include <optional>
#include <string>
#include <vector>

namespace Quantinuum::QuantumOrigin::Cli
{
    YAML::Node cfgFromFile(const std::string &configPath);

    class ConfigError : public std::runtime_error
    {
      public:
        ConfigError(std::string filename, const std::string &msg);

      private:
        std::string filename;
    };

    class ConfigYamlError : public ConfigError
    {
      public:
        ConfigYamlError(std::string filename, const YAML::Exception &ex);

      private:
        const YAML::Exception &ex;
    };

    class KeyParametersConfig
    {
      public:
        explicit KeyParametersConfig(const YAML::Node &cfg);
        KeyParametersConfig() = default;
        KeyParametersConfig(
            const std::string &nonceFormatString, const std::string &nonceString, std::string keyParameters, std::optional<Common::KeyAlgorithm> keyAlgorithm,
            const std::string &sharedSecretFormatString, const std::string &sharedSecretString);
        KeyParametersConfig(std::vector<uint8_t> nonce, std::string keyParameters, std::optional<Common::KeyAlgorithm> keyAlgorithm, std::vector<uint8_t> sharedSecret);

        [[nodiscard]] const std::vector<uint8_t> &getNonce() const
        {
            return nonce;
        }

        [[nodiscard]] const std::string &getKeyParameters() const
        {
            return keyParameters;
        }

        [[nodiscard]] const std::optional<Common::KeyAlgorithm> &getKeyAlgorithm() const
        {
            return keyAlgorithm;
        }

        [[nodiscard]] const std::optional<Common::KeyType> &getKeyType() const
        {
            return keyType;
        }

        [[nodiscard]] const std::optional<Common::KeyType> &getLocalKeyType() const
        {
            return localKeyType;
        }

        [[nodiscard]] const std::vector<uint8_t> &getSharedSecret() const
        {
            return sharedSecret;
        }

      private:
        std::vector<uint8_t> nonce;
        std::string keyParameters;
        std::optional<Common::KeyType> keyType;
        std::optional<Common::KeyAlgorithm> keyAlgorithm;
        std::optional<Common::KeyType> localKeyType;
        std::vector<uint8_t> sharedSecret;
    };

    class CredentialsConfig
    {
      public:
        explicit CredentialsConfig(const YAML::Node &cfg);
        CredentialsConfig() = default;
        CredentialsConfig(std::string certificatePath, std::string privateKeyPath, std::string url, std::string clientId, std::string apiKey);
        [[nodiscard]] const std::string &getCertificate() const
        {
            return certificatePath;
        }

        [[nodiscard]] const std::string &getPrivateKeyForCert() const
        {
            return privateKeyPath;
        }

        [[nodiscard]] const std::string &getApiKey() const
        {
            return apiKey;
        }

        [[nodiscard]] const std::string &getUrl() const
        {
            return url;
        }

        [[nodiscard]] const std::string &getClientId() const
        {
            return clientId;
        }

      private:
        std::string certificatePath;
        std::string privateKeyPath;
        std::string apiKey;
        std::string url;
        std::string clientId;
    };

    class GeneralConfig
    {
      public:
        explicit GeneralConfig(const YAML::Node &cfg);
        GeneralConfig() = default;
        GeneralConfig(
            std::string onboardingAuth, std::string outputFilename, spdlog::level::level_enum logLevel = spdlog::level::warn,
            std::optional<Cli::Commands::OutputFormat> outputFormat = std::nullopt);

        [[nodiscard]] const std::string &getOnboardingAuth() const
        {
            return onboardingAuth;
        }

        [[nodiscard]] const std::optional<Cli::Commands::OutputFormat> &getOutputFormat() const
        {
            return outputFormat;
        }

        [[nodiscard]] const std::string &getOutputFilename() const
        {
            return outputFilename;
        }

        [[nodiscard]] const std::optional<spdlog::level::level_enum> &getLevel() const
        {
            return logLevel;
        }

      private:
        std::string onboardingAuth;
        std::optional<Cli::Commands::OutputFormat> outputFormat;
        std::string outputFilename;
        std::optional<spdlog::level::level_enum> logLevel;
    };


} // namespace Quantinuum::QuantumOrigin::Cli
