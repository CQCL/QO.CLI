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
#include "command.h"

#include <cppcodec/base64_default_rfc4648.hpp>
#include <cppcodec/hex_default_lower.hpp>
#include <qo_cloud_kms/context.h>
#include <qo_cloud_kms/create_key.h>
#include <qo_cloud_kms/request.h>

#include <random>

namespace Quantinuum::QuantumOrigin::Cli::Commands::Byok::Aws
{

    ByokAwsCommand::ByokAwsCommand(const ByokParameters &byokParams) : CommandBase(byokParams) {}

    void ByokAwsCommand::useConfigParameters()
    {
        const auto &config = getConfig();
        if (config)
        {
            if (getParameters().alias.empty())
            {
                getParameters().alias = config->getAwsConfig().getAlias();
            }
            if (getParameters().description.empty())
            {
                getParameters().description = config->getAwsConfig().getDescription();
            }
            if (getParameters().expiryDate.empty())
            {
                getParameters().expiryDate = config->getAwsConfig().getExpiryDate();
            }
            if (getParameters().profile.empty())
            {
                getParameters().profile = config->getAwsConfig().getProfile();
            }
        }
    }

    void ByokAwsCommand::checkParameters()
    {
        // All parameters are optional
    }

    void ByokAwsCommand::execute()
    {
        auto sharedSecret = hex::encode(getParameters().byokParams.decryptionParameters.sharedSecret);
        auto nonce        = base64::encode(getParameters().byokParams.decryptionParameters.nonce);

        std::optional<std::string> apiKey;
        if (!getParameters().byokParams.apiParameters.authParameters.apiKey.empty())
        {
            apiKey = getParameters().byokParams.apiParameters.authParameters.apiKey;
        }

        std::unique_ptr<Context> context;
        if (getParameters().byokParams.apiParameters.authParameters.clientId.empty())
        {
            context = std::make_unique<Context>(
                getParameters().profile, sharedSecret, getParameters().byokParams.apiParameters.url,
                getParameters().byokParams.apiParameters.authParameters.clientCertificateFilename, Common::CertType::PEM,
                getParameters().byokParams.apiParameters.authParameters.privateKeyFilename, apiKey);
        }
        else
        {
            context = std::make_unique<Context>(
                getParameters().profile, sharedSecret, getParameters().byokParams.apiParameters.url, getParameters().byokParams.apiParameters.authParameters.clientId,
                apiKey);
        }

        Request request{getParameters().alias, getParameters().expiryDate, getParameters().description, nonce};
        spdlog::info("Calling QO_kms_aws_create_key");

        if (QO_kms_aws_create_key(*context, request) == 0)
        {
            spdlog::info("KMS imported successfully");
        }
        else
        {
            spdlog::error("KMS failed to import. Turn on logging for more info");
        }
    }

} // namespace Quantinuum::QuantumOrigin::Cli::Commands::Byok::Aws
