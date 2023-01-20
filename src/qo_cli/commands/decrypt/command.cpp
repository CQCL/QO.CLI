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
#include "decrypt.h"
#include "key_file.h"

namespace Quantinuum::QuantumOrigin::Cli::Commands::Decrypt
{

    void DecryptCommand::useConfigParameters()
    {
        const auto &config = getConfig();
        if (config)
        {
            if (getParameters().decryptionParameters.nonce.empty())
            {
                getParameters().decryptionParameters.nonce = config->getKeyParametersConfig().getNonce();
            }
            if (!getParameters().outputParameters.outputFormat)
            {
                getParameters().outputParameters.outputFormat = config->getGeneralConfig().getOutputFormat();
            }
            if (getParameters().outputParameters.outputFilename.empty())
            {
                getParameters().outputParameters.outputFilename = config->getGeneralConfig().getOutputFilename();
            }
            if (getParameters().decryptionParameters.sharedSecret.empty())
            {
                getParameters().decryptionParameters.sharedSecret = config->getKeyParametersConfig().getSharedSecret();
            }
        }
    }

    void DecryptCommand::checkParameters()
    {
        /////////////////////////////////
        // Get Data from File, maybe
        /////////////////////////////////
        // If an input file is supplied, then this will override individual params
        if (!getParameters().inputFilename.empty() || getParameters().seed.empty() || getParameters().encryptedNewKey.empty())
        {
            if (getParameters().inputFilename.empty())
            {
                throw std::runtime_error("Either seed/encrypted key or input file must be provided");
            }

            try
            {
                KeyFile keyFile;

                keyFile.getGcmFieldsFromKeygenResponse(getParameters().inputFilename);

                try
                {
                    auto keyTypeString                = keyFile.GetContentType();
                    getParameters().keyTypeAndVariant = parseKeyTypeAndVariantString(keyTypeString);
                }
                catch (const std::exception &ex)
                {
                    spdlog::warn("Failed to parse key type from file: {}", ex.what());
                }

                getParameters().counter         = keyFile.GetGcmCounter();
                getParameters().encryptedNewKey = keyFile.GetGcmEncryptedData();
                getParameters().seed            = keyFile.GetGcmSeed();
            }
            catch (const nlohmann::detail::parse_error &ex)
            {
                spdlog::error("ERROR: Failed with JSON parse_error exception: {}", ex.what());
            }
        }

        if (!getParameters().keyTypeAndVariant)
        {
            spdlog::warn("No key type has been specified, treating key as generic");
        }

        if (getParameters().decryptionParameters.sharedSecret.empty())
        {
            throw MissingParameterError("Shared secret");
        }
    }

    void DecryptCommand::execute()
    {
        spdlog::info("Working on [keydecrypt]");
        spdlog::info("Encoded payload len = {}", getParameters().encryptedNewKey.size());

        CliDecrypt keyDecrypt(
            getParameters().decryptionParameters.sharedSecret, getParameters().decryptionParameters.nonce, getParameters().seed, getParameters().counter,
            getParameters().encryptedNewKey, getParameters().keyTypeAndVariant);
        keyDecrypt.runDecrypt(getParameters().outputParameters.outputFormat, getParameters().outputParameters.getOutputStream());
    }

} // namespace Quantinuum::QuantumOrigin::Cli::Commands::Decrypt
