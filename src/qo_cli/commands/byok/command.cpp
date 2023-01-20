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
#include "aws/command.h"
#include "az/command.h"

#include <random>
#include <vector>

namespace Quantinuum::QuantumOrigin::Cli::Commands::Byok
{

    ByokCommand::ByokCommand()
    {
        // Add the AWS-specific BYOK subcommand
        addNewSubcommand(std::make_unique<Aws::ByokAwsCommand>(getParameters()));
        // Add the Azure-specific BYOK subcommand
        addNewSubcommand(std::make_unique<Az::ByokAzCommand>(getParameters()));
    }

    void ByokCommand::useConfigParameters()
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
            if (getParameters().decryptionParameters.nonce.empty())
            {
                getParameters().decryptionParameters.nonce = config->getKeyParametersConfig().getNonce();
            }
            if (getParameters().decryptionParameters.sharedSecret.empty())
            {
                getParameters().decryptionParameters.sharedSecret = config->getKeyParametersConfig().getSharedSecret();
            }
            if (getParameters().apiParameters.url.empty())
            {
                getParameters().apiParameters.url = config->getCredentialsConfig().getUrl();
            }
        }
    }

    void ByokCommand::checkParameters()
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

        if (getParameters().decryptionParameters.sharedSecret.empty())
        {
            throw MissingParameterError("Shared secret");
        }

        if (getParameters().decryptionParameters.nonce.empty())
        {
            // Generate random nonce if one wasn't supplied
            spdlog::debug("No nonce supplied, generating random nonce");

            std::vector<uint8_t> nonce(16);

            std::random_device randomDevice;
            std::independent_bits_engine<std::default_random_engine, sizeof(uint8_t), uint8_t> randomBitsEngine(randomDevice());
            std::generate(begin(nonce), end(nonce), std::ref(randomBitsEngine));

            getParameters().decryptionParameters.nonce = nonce;
        }
    }

    void ByokCommand::execute()
    {
        throw std::runtime_error("The BYOK command requires a subcommand");
    }

} // namespace Quantinuum::QuantumOrigin::Cli::Commands::Byok
