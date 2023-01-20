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

#include <qo_common/parameters.h>

#include <magic_enum.hpp>
#include <spdlog/fmt/bin_to_hex.h>
#include <spdlog/spdlog.h>

#include <unordered_map>

namespace Quantinuum::QuantumOrigin::Cli::Commands::Keygen
{

    std::unordered_map<std::string, Common::KeyType> keyTypeMap{
  // Classical algorithms
        {             "AES",              Common::KeyType::AES},
        {             "RSA",              Common::KeyType::RSA},
        {              "EC",               Common::KeyType::EC},

 // PQC KEM algorithms
        {            "BIKE",             Common::KeyType::BIKE},
        {"CLASSIC-MCELIECE", Common::KeyType::CLASSIC_MCELIECE},
        {             "HQC",              Common::KeyType::HQC},
        {           "KYBER",            Common::KeyType::KYBER},
        {      "NTRU-PRIME",       Common::KeyType::NTRU_PRIME},

 // PQC signature algorithms
        {       "DILITHIUM",        Common::KeyType::DILITHIUM},
        {          "FALCON",           Common::KeyType::FALCON},
        {         "SPHINCS",          Common::KeyType::SPHINCS},
    };

    void KeygenParameters::print() const
    {
        spdlog::debug("cert                  = \"{}\"", apiParameters.authParameters.clientCertificateFilename);
        spdlog::debug("privateKeyForCert     = \"{}\"", apiParameters.authParameters.privateKeyFilename);
        spdlog::debug("keyType               = \"{}\"", keyType ? magic_enum::enum_name(*keyType) : "not set (Default)");
        spdlog::debug("keyparameters         = \"{}\"", keyParameters.json);
        spdlog::debug("url                   = \"{}\"", apiParameters.url);
        spdlog::debug("nonce                 = \"{}\"", spdlog::to_hex(std::begin(decryptionParameters.nonce), std::end(decryptionParameters.nonce)));
        spdlog::debug("sharedSecret          = \"{}\"", spdlog::to_hex(std::begin(decryptionParameters.sharedSecret), std::end(decryptionParameters.sharedSecret)));
        spdlog::debug("outputFormat          = \"{}\"", outputParameters.outputFormat ? magic_enum::enum_name(*outputParameters.outputFormat) : "not set (Default)");
        spdlog::debug("outputFilename        = \"{}\"", outputParameters.outputFilename);
        spdlog::debug("ApiKey                = \"{}\"", apiParameters.authParameters.apiKey);
        spdlog::debug("ClientID              = \"{}\"", apiParameters.authParameters.clientId);
    }

} // namespace Quantinuum::QuantumOrigin::Cli::Commands::Keygen
