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
#include "decryption_parameters.h"

#include <qo_decrypt/qo_cleanse.h>

namespace Quantinuum::QuantumOrigin::Cli::Commands
{

    DecryptionParameters::DecryptionParameters() : nonceDataParameter("nonce"), sharedSecretDataParameter("shared secret") {}

    DecryptionParameters::~DecryptionParameters()
    {
        CleanseStdVector(nonce);
        CleanseStdVector(sharedSecret);
    }

    void DecryptionParameters::addParametersToCli(CLI::App &parent)
    {
        // Add a subcommand with no name, which allows us to set a separate callback for these parameters
        // from any callback that might be set on the parent
        auto decryptionParameters = parent.add_subcommand()->silent();

        CLI::Option *optNonceFormat = decryptionParameters
                                          ->add_option(
                                              "--nonceformat,-N", nonceDataParameter.getFormat(),
                                              "Format of the supplied --nonce value. Accepted formats are [base64,hex]. Optional. Default=base64.")
                                          ->default_val(Cli::Commands::DataFormat::Base64);
        CLI::Option *optNonce = decryptionParameters->add_option(
            "--nonce,-n", nonceDataParameter.getDataString(), "Nonce to be used in the request. DefaultFormat=base64. Redirect with @file.");

        optNonceFormat->needs(optNonce)->group("Decryption");
        optNonce->envname("QO_NONCE")->group("Decryption");

        optNonce->transform(transformFilenameToValue);
        optNonceFormat->transform(CLI::CheckedTransformer(dataFormatMap, CLI::ignore_case));

#ifdef INCLUDE_SUPPORT_FOR_KEYDECRYPT
        CLI::Option *optSharedSecretFormat = decryptionParameters
                                                 ->add_option(
                                                     "--sharedsecretformat,-K", sharedSecretDataParameter.getFormat(),
                                                     "Format of the --sharedsecret value. Accepted formats are [base64,hex]. Optional. Default=base64.")
                                                 ->default_val(Cli::Commands::DataFormat::Base64);
        CLI::Option *optSharedSecret = decryptionParameters->add_option(
            "--sharedsecret,-k", sharedSecretDataParameter.getDataString(),
            "SharedSecret as provided during onboarding. DefaultFormat=base64. Redirect with @file. Mandatory.");

        optSharedSecretFormat->needs(optSharedSecret)->group("Decryption");
        optSharedSecret->envname("QO_SECRET")->group("Decryption");

        optSharedSecret->transform(transformFilenameToValue);
        optSharedSecretFormat->transform(CLI::CheckedTransformer(dataFormatMap, CLI::ignore_case));
#endif

        decryptionParameters->callback(
            [&]()
            {
                // Parse the string/format pairs into byte vectors
                nonce = nonceDataParameter.getData();
#ifdef INCLUDE_SUPPORT_FOR_KEYDECRYPT
                sharedSecret = sharedSecretDataParameter.getData();
#endif
            });
    }

} // namespace Quantinuum::QuantumOrigin::Cli::Commands
