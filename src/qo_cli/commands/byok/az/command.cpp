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
#include "utils.h"

#include <cppcodec/base64_url.hpp>
#include <iostream>
#include <qo_common/service.h>
#include <qo_decrypt/qo_crypto.h>
#include <random>
#include <spdlog/spdlog.h>

namespace Quantinuum::QuantumOrigin::Cli::Commands::Byok::Az
{
#define PAYLOAD_DATA_MINIMUM_LEN (16) // AES128 is currently the smallest key request that we support
#define PAYLOAD_TAG_LEN          (16)

    ByokAzCommand::ByokAzCommand(const ByokParameters &byokParams) : CommandBase(byokParams) {}

    void ByokAzCommand::useConfigParameters()
    {
        const auto &config = getConfig();
        if (config)
        {
            if (getParameters().kId.empty())
            {
                getParameters().kId = config->getAzConfig().getKid();
            }
            if (getParameters().pemFileName.empty())
            {
                getParameters().pemFileName = config->getAzConfig().getPemFileName();
            }
            if (!getParameters().keyType)
            {
                getParameters().keyType = config->getKeyParametersConfig().getKeyType();
            }
            if (getParameters().keyParameters.json.empty())
            {
                getParameters().keyParameters.json = config->getKeyParametersConfig().getKeyParameters();
            }
            if (getParameters().outputParameters.outputFilename.empty())
            {
                getParameters().outputParameters.outputFilename = config->getGeneralConfig().getOutputFilename();
            }
        }
    }

    void ByokAzCommand::checkParameters()
    {
        if (getParameters().pemFileName.empty())
        {
            throw MissingParameterError("PEM file");
        }
        if (getParameters().kId.empty())
        {
            throw MissingParameterError("KEK Id");
        }
    }

    void ByokAzCommand::execute()
    {
        spdlog::info("Working on [Azure]");
        std::unique_ptr<Common::Connection> keyGenConnection;
        if (getParameters().byokParams.apiParameters.authParameters.clientId.empty())
        {
            // clientId is not present, we use the cert+key based ctor
            keyGenConnection = std::make_unique<Common::Connection>(
                getParameters().byokParams.apiParameters.url, getParameters().byokParams.apiParameters.authParameters.clientCertificateFilename, Common::CertType::PEM,
                getParameters().byokParams.apiParameters.authParameters.privateKeyFilename, getParameters().byokParams.apiParameters.authParameters.apiKey);
        }
        else
        {
            // clientId is present, we use the matching ctor.
            keyGenConnection = std::make_unique<Common::Connection>(
                getParameters().byokParams.apiParameters.url, getParameters().byokParams.apiParameters.authParameters.clientId,
                getParameters().byokParams.apiParameters.authParameters.apiKey);
        }

        std::string outString = getPEM(getParameters().pemFileName);

        nlohmann::json payload(nlohmann::json::parse(getParameters().keyParameters.json));
        payload["format"] = "PKCS8";

        Common::KeyRequest keyRequest(
            getParameters().keyType.value_or(Common::KeyTypeEnum::Enum::RSA), payload.dump(), getParameters().byokParams.decryptionParameters.nonce,
            Quantinuum::QuantumOrigin::Common::EncryptionScheme::HKDF_AES_GCM, false);
        keyRequest.addRsaKeyEncryption(outString, true, Quantinuum::QuantumOrigin::Common::OaepHashFunctionEnum::Enum::SHA_1);

        auto keyResponse = Utils::sendRequestWithRetries(*keyGenConnection, keyRequest);

        spdlog::info("Working on [.byok output]");
        spdlog::debug("Encoded payload len = {}", keyResponse.encrypted.encryptedData.size());

        // The encryptedNewKey param contains the encrypted key + a 16 byte tag
        // and GCM produces as much data out as you put in.
        // So, in theory, we only need storage for the entire encrypted_data, less 16
        if (keyResponse.encrypted.encryptedData.size() < (PAYLOAD_DATA_MINIMUM_LEN + PAYLOAD_TAG_LEN))
        {
            // The supplied value for newkey is too short to contain both the newkey and the 16 byte GCM tag
            const std::string errMsg =
                "ERROR: The supplied value for \"encryptedkey\" (" + std::to_string(keyResponse.encrypted.encryptedData.size()) + " bytes) is too short";
            spdlog::trace(errMsg.c_str());
            throw std::runtime_error(
                "ERROR: The supplied value for \"encryptedkey\" (" + std::to_string(keyResponse.encrypted.encryptedData.size()) + " bytes) is too short");
        }

        size_t cbPlainTextOut              = (size_t)(keyResponse.encrypted.encryptedData.size() - PAYLOAD_TAG_LEN);
        std::vector<uint8_t> pPlainTextOut = std::vector<uint8_t>(cbPlainTextOut);

        spdlog::trace("DEBUG: cbPlainTextOut = {}", pPlainTextOut.size());
        size_t plainTextBytesWritten = 0;

        spdlog::trace("Decrypting");
        int rc = qo_decrypt_aes_gcm(
            getParameters().byokParams.decryptionParameters.sharedSecret.data(), getParameters().byokParams.decryptionParameters.sharedSecret.size(), // 32
            keyResponse.encrypted.encryptedData.data(), keyResponse.encrypted.encryptedData.size(),                                                   // >= 16
            keyResponse.encrypted.seed.data(), keyResponse.encrypted.seed.size(),                                                                     // 36
            keyResponse.encrypted.counter,                                                                                              // counter typically starts at 0
            getParameters().byokParams.decryptionParameters.nonce.data(), getParameters().byokParams.decryptionParameters.nonce.size(), // authenticated_data
            pPlainTextOut.data(), pPlainTextOut.size(),                                                                                 // >= cipher_len - 16
            &plainTextBytesWritten);
        if (rc != 0)
        {
            std::string err = qo_decrypt_error_description(rc);
            spdlog::error("Decrypt failed with return code {}: {}", rc, err);
            throw std::runtime_error("Decrypt failed with return code " + std::to_string(rc) + ": " + err);
        }
        pPlainTextOut.resize(plainTextBytesWritten);
        outputByok(pPlainTextOut, getParameters().outputParameters.getOutputStream());
    }

    std::string ByokAzCommand::getPEM(std::string fileName)
    {
        std::ifstream inStream(fileName);
        std::stringstream buffer;
        buffer << inStream.rdbuf();
        std::string outString = buffer.str();

        spdlog::info("PEM file [{}] extracted to [{}]", fileName, outString);
        return outString;
    }

    void ByokAzCommand::outputByok(std::vector<uint8_t> plainTextOut, std::ostream &outputStream)
    {
        std::string encodedString = cppcodec::base64_url::encode(plainTextOut.data(), plainTextOut.size());

        nlohmann::json hsmJson{
            {"schema_version",             "1.0.0"},
            {     "generator", "SoftKEY BYOK Tool"}
        };
        hsmJson["ciphertext"] = encodedString;
        hsmJson["header"]     = nlohmann::json({
            {"kid",    getParameters().kId},
            {"alg",                  "dir"},
            {"enc", "CKM_RSA_AES_KEY_WRAP"}
        });
        spdlog::trace(hsmJson.dump());

        outputStream << hsmJson.dump();
        outputStream.flush();


        spdlog::info("Byok file now created. To import into azure use");
        if (getParameters().keyType == Common::KeyTypeEnum::Enum::EC)
        {
            spdlog::info(
                "az keyvault key import --vault-name [value-name] --name [target key name] --byok-file {} --kty EC --curve [curve-name]",
                getParameters().outputParameters.outputFilename);
        }
        else
        {
            spdlog::info("az keyvault key import --vault-name [value-name] --name [target key name] --byok-file {}", getParameters().outputParameters.outputFilename);
        }
    }

} // namespace Quantinuum::QuantumOrigin::Cli::Commands::Byok::Az
