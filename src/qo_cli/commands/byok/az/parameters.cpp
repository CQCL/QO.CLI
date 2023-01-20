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
#include "parameters.h"

#include <magic_enum.hpp>
#include <spdlog/fmt/bin_to_hex.h>
#include <spdlog/spdlog.h>

namespace Quantinuum::QuantumOrigin::Cli::Commands::Byok::Az
{

    std::unordered_map<std::string, Common::KeyType> keyTypeMap{
  // Supported algorithms
        {"RSA", Common::KeyType::RSA},
        { "EC",  Common::KeyType::EC}
    };

    ByokAzParameters::ByokAzParameters(const ByokParameters &byokParams) : byokParams(byokParams) {}

    void ByokAzParameters::print() const
    {
        spdlog::debug("ByokAzParameters");
        spdlog::debug("cert                  = \"{}\"", byokParams.apiParameters.authParameters.clientCertificateFilename);
        spdlog::debug("privateKeyForCert     = \"{}\"", byokParams.apiParameters.authParameters.privateKeyFilename);
        spdlog::debug("keyType               = \"{}\"", keyType ? magic_enum::enum_name(*keyType) : "not set (Default)");
        spdlog::debug("keyparameters         = \"{}\"", keyParameters.json);
        spdlog::debug("url                   = \"{}\"", byokParams.apiParameters.url);
        spdlog::debug(
            "nonce                 = \"{}\"", spdlog::to_hex(std::begin(byokParams.decryptionParameters.nonce), std::end(byokParams.decryptionParameters.nonce)));
        spdlog::debug(
            "sharedSecret          = \"{}\"",
            spdlog::to_hex(std::begin(byokParams.decryptionParameters.sharedSecret), std::end(byokParams.decryptionParameters.sharedSecret)));
        spdlog::debug("outputFilename        = \"{}\"", outputParameters.outputFilename);
        spdlog::debug("ApiKey                = \"{}\"", byokParams.apiParameters.authParameters.apiKey);
        spdlog::debug("ClientID              = \"{}\"", byokParams.apiParameters.authParameters.clientId);
        spdlog::debug("Pem Filename          = \"{}\"", pemFileName);
    }

} // namespace Quantinuum::QuantumOrigin::Cli::Commands::Byok::Az
