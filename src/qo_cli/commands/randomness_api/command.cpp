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

#ifdef INCLUDE_SUPPORT_FOR_KEYDECRYPT
#include "decrypt.h"
#endif

#include <qo_common/randomness_request.h>
#include <qo_common/service.h>

#include <spdlog/fmt/bin_to_hex.h>
#include <spdlog/spdlog.h>

#include <random>

namespace Quantinuum::QuantumOrigin::Cli::Commands::RandomnessApi
{

    void RandomnessApiCommand::useConfigParameters()
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
            if (getParameters().decryptionParameters.nonce.empty())
            {
                getParameters().decryptionParameters.nonce = config->getKeyParametersConfig().getNonce();
            }
            if (getParameters().decryptionParameters.sharedSecret.empty())
            {
                getParameters().decryptionParameters.sharedSecret = config->getKeyParametersConfig().getSharedSecret();
            }
            if (getParameters().apiParameters.authParameters.apiKey.empty())
            {
                getParameters().apiParameters.authParameters.apiKey = config->getCredentialsConfig().getApiKey();
            }
            if (getParameters().apiParameters.authParameters.clientId.empty())
            {
                getParameters().apiParameters.authParameters.clientId = config->getCredentialsConfig().getClientId();
            }
            if (!getParameters().outputParameters.outputFormat)
            {
                getParameters().outputParameters.outputFormat = config->getGeneralConfig().getOutputFormat();
            }
            if (getParameters().outputParameters.outputFilename.empty())
            {
                getParameters().outputParameters.outputFilename = config->getGeneralConfig().getOutputFilename();
            }
        }
    }

    void RandomnessApiCommand::checkParameters()
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

#ifdef INCLUDE_SUPPORT_FOR_KEYDECRYPT
        if (getParameters().decryptionParameters.sharedSecret.empty())
        {
            throw MissingParameterError("Shared secret");
        }
#endif

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

    void RandomnessApiCommand::execute()
    {
        spdlog::debug("Working on [randomness]");

        std::unique_ptr<Common::Connection> randomnessConnection;
        if (getParameters().apiParameters.authParameters.clientId.empty())
        {
            // clientId is not present, we use the cert+key based ctor
            randomnessConnection = std::make_unique<Common::Connection>(
                getParameters().apiParameters.url, getParameters().apiParameters.authParameters.clientCertificateFilename, Common::CertType::PEM,
                getParameters().apiParameters.authParameters.privateKeyFilename, getParameters().apiParameters.authParameters.apiKey);
        }
        else
        {
            // clientId is present, we use the matching ctor.
            randomnessConnection = std::make_unique<Common::Connection>(
                getParameters().apiParameters.url, getParameters().apiParameters.authParameters.clientId, getParameters().apiParameters.authParameters.apiKey);
        }

        Quantinuum::QuantumOrigin::Common::RandomnessRequest randRequest(getParameters().randSize, getParameters().decryptionParameters.nonce);
        auto randResponse = Utils::sendRequestWithRetries(*randomnessConnection, randRequest);
        auto &resp        = randResponse.encrypted[0];

#ifdef INCLUDE_SUPPORT_FOR_KEYDECRYPT
        spdlog::info("Working on [decrypt randomness]");
        spdlog::debug("Encoded payload len = {}", resp.encryptedData.size());

        CliDecrypt randDecrypt(
            getParameters().decryptionParameters.sharedSecret, getParameters().decryptionParameters.nonce, resp.seed, resp.counter, resp.encryptedData,
            KeyTypeAndVariant{CliLocal_Key_Type::KEY_TYPE_RAND, 0});
        randDecrypt.runDecrypt(getParameters().outputParameters.outputFormat, getParameters().outputParameters.getOutputStream());
#else
        spdlog::info("Encrypted response: {}", spdlog::to_hex(std::begin(resp.encryptedData), std::end(resp.encryptedData)));
#endif // INCLUDE_SUPPORT_FOR_KEYDECRYPT
    }

} // namespace Quantinuum::QuantumOrigin::Cli::Commands::RandomnessApi
