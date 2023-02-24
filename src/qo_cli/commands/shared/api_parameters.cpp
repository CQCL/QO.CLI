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
#include "api_parameters.h"

#include <qo_common/parameters.h>
#include <qo_decrypt/qo_cleanse.h>

namespace Quantinuum::QuantumOrigin::Cli::Commands
{

    const std::unordered_map<std::string, Common::KeyAlgorithm> keyAlgorithmMap{
  // Classical algorithms
        {             "AES",              Common::KeyAlgorithm::AES},
        {             "RSA",              Common::KeyAlgorithm::RSA},
        {              "EC",               Common::KeyAlgorithm::EC},

 // PQC KEM algorithms
        {            "BIKE",             Common::KeyAlgorithm::BIKE},
        {"CLASSIC-MCELIECE", Common::KeyAlgorithm::CLASSIC_MCELIECE},
        {             "HQC",              Common::KeyAlgorithm::HQC},
        {           "KYBER",            Common::KeyAlgorithm::KYBER},
        {      "NTRU-PRIME",       Common::KeyAlgorithm::NTRU_PRIME},

 // PQC signature algorithms
        {       "DILITHIUM",        Common::KeyAlgorithm::DILITHIUM},
        {          "FALCON",           Common::KeyAlgorithm::FALCON},
        {         "SPHINCS",          Common::KeyAlgorithm::SPHINCS},
    };

    AuthParameters::~AuthParameters()
    {
        CleanseStdString(apiKey);
        CleanseStdString(clientId);
    }

    void AuthParameters::addParametersToCli(CLI::App &parent)
    {
        CLI::Option *optCertificate =
            parent.add_option("--cert,-c", clientCertificateFilename, "Certificate to be used in the request. DefaultFormat=pem. Redirect with @file. Mandatory.");
        CLI::Option *optCertificatePrivateKey = parent.add_option("--certkey,-z", privateKeyFilename, "Certificate's private key. Redirect with @file. Mandatory.");

        CLI::Option *optApiKey   = parent.add_option("--api-key,-A", apiKey, "QO API Key, required for authentication with the API.");
        CLI::Option *optClientId = parent.add_option("--client_id,-C", clientId, "client ID of the onboarded user.");

        optCertificate->group("Authentication")->envname("QO_CERT")->check(CLI::ExistingFile);
        optCertificatePrivateKey->group("Authentication")->envname("QO_KEY")->check(CLI::ExistingFile);
        optApiKey->group("Authentication")->envname("QO_API_KEY");
        optClientId->group("Authentication")->envname("QO_CLIENT_ID");
    }

    void ApiParameters::addParametersToCli(CLI::App &parent)
    {
        authParameters.addParametersToCli(parent);

        CLI::Option *optTargetURL = parent.add_option("--url,-u", url, "URL of the Quantum Origin API. Mandatory.");

        optTargetURL->group("API")->envname("QO_URL");
    }

} // namespace Quantinuum::QuantumOrigin::Cli::Commands
