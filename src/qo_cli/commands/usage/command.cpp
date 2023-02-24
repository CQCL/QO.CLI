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
#include "utils.h"

#include <qo_common/randomness_request.h>
#include <qo_common/service.h>
#include <qo_common/usage_request.h>

#include <spdlog/fmt/bin_to_hex.h>
#include <spdlog/spdlog.h>

#include <random>

namespace Quantinuum::QuantumOrigin::Cli::Commands::Usage
{

    void UsageCommand::useConfigParameters()
    {
        const auto &config = getConfig();
        if (config)
        {
            if (getParameters().apiParameters.authParameters.clientCertificateFilename.empty())
            {
                getParameters().apiParameters.authParameters.clientCertificateFilename = config->getCredentialsConfig().getCertificate();
            }
            if (getParameters().apiParameters.authParameters.privateKeyFilename.empty())
            {
                getParameters().apiParameters.authParameters.privateKeyFilename = config->getCredentialsConfig().getPrivateKeyForCert();
            }
            if (getParameters().apiParameters.url.empty())
            {
                getParameters().apiParameters.url = config->getCredentialsConfig().getUrl();
            }
            if (getParameters().apiParameters.authParameters.apiKey.empty())
            {
                getParameters().apiParameters.authParameters.apiKey = config->getCredentialsConfig().getApiKey();
            }
            if (getParameters().apiParameters.authParameters.clientId.empty())
            {
                getParameters().apiParameters.authParameters.clientId = config->getCredentialsConfig().getClientId();
            }
            if (getParameters().outputParameters.outputFilename.empty())
            {
                getParameters().outputParameters.outputFilename = config->getGeneralConfig().getOutputFilename();
            }
        }
    }

    void UsageCommand::checkParameters()
    {
        if (getParameters().apiParameters.authParameters.clientId.empty())
        {
            if (getParameters().apiParameters.authParameters.clientCertificateFilename.empty() || getParameters().apiParameters.authParameters.privateKeyFilename.empty())
            {
                throw std::runtime_error("Either a client ID or client cert/key parameters are required");
            }
        }

        if (getParameters().apiParameters.url.empty())
        {
            throw MissingParameterError("URL");
        }

        if (getParameters().invalidTimeOrder())
        {
            throw UsageParametersException("The From date: " + getParameters().from + " is after the To date: " + getParameters().to);
        }
    }

    void UsageCommand::execute()
    {
        spdlog::debug("Working on [usage]");

        std::unique_ptr<Common::Connection> usageConnection;
        if (getParameters().apiParameters.authParameters.clientId.empty())
        {
            // clientId is not present, we use the cert+key based ctor
            usageConnection = std::make_unique<Common::Connection>(
                getParameters().apiParameters.url, getParameters().apiParameters.authParameters.clientCertificateFilename, Common::CertType::PEM,
                getParameters().apiParameters.authParameters.privateKeyFilename, getParameters().apiParameters.authParameters.apiKey);
        }
        else
        {
            // clientId is present, we use the matching ctor.
            usageConnection = std::make_unique<Common::Connection>(
                getParameters().apiParameters.url, getParameters().apiParameters.authParameters.clientId, getParameters().apiParameters.authParameters.apiKey);
        }

        Quantinuum::QuantumOrigin::Common::UsageRequest usageRequest(getParameters().from, getParameters().to, getParameters().groupBy);
        auto randResponse = Utils::sendRequestWithRetries(*usageConnection, usageRequest);
        spdlog::info(randResponse.contentStr);

        getParameters().outputParameters.getOutputStream() << randResponse.contentStr;
    }

} // namespace Quantinuum::QuantumOrigin::Cli::Commands::Usage
