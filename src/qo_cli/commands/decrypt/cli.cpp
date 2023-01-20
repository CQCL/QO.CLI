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
#include "cli.h"

namespace Quantinuum::QuantumOrigin::Cli::Commands::Decrypt
{

    DecryptCliCommand::DecryptCliCommand()
        : CliCommand("keydecrypt", "Decrypt a received key.", {"kd"}), seedDataParameter("seed"), encryptedNewKeyDataParameter("encrypted data")
    {
    }

    void DecryptCliCommand::addParameters(CLI::App &parent, DecryptParameters &parameters)
    {
        parameters.decryptionParameters.addParametersToCli(parent);
        parameters.outputParameters.addParametersToCli(parent);

        ////////////////////////////////////
        // Options for Command: KeyDecrypt
        ////////////////////////////////////

        CLI::Option *optKeyDecryptCipherTextSeedFormat =
            parent
                .add_option("--seedformat,-S", seedDataParameter.getFormat(), "Format of the --seed value. Accepted formats are [base64,hex]. Optional. Default=base64.")
                ->default_val(Cli::Commands::DataFormat::Base64);
        CLI::Option *optKeyDecryptCipherTextSeed = parent.add_option(
            "--seed,-s", seedDataParameter.getDataString(),
            "Seed value as received in the keygen response as \"seed\". DefaultFormat=base64. Redirect with @file. Optional.");

        CLI::Option *optKeyDecryptCipherTextNewKeyFormat =
            parent
                .add_option(
                    "--encryptedkeyformat,--encrypteddataformat,-E", encryptedNewKeyDataParameter.getFormat(),
                    "Format of the --encryptedkey/data value. Accepted formats are [base64,hex]. Optional. Default=base64.")
                ->default_val(Cli::Commands::DataFormat::Base64);
        CLI::Option *optKeyDecryptCipherTextNewKey = parent.add_option(
            "--encryptedkey,--encrypteddata,-e", encryptedNewKeyDataParameter.getDataString(),
            "Encrypted value as received in the keygen response as \"encrypted_data\" (or \"encrypted_key\"). DefaultFormat=base64. Redirect with @file. Optional.");

        CLI::Option *optKeyDecryptCipherTextCounter =
            parent.add_option("--counter,-c", parameters.counter, "Starting counter value as received in the keygen response as \"counter\". Optional. default=0");

        CLI::Option *optKeyDecryptInputFilename = parent.add_option(
            "--inputfile,-i", parameters.inputFilename,
            "Filename from where to read the keygen response. The data must be supplied in json+base64 format. Optional. Default=stdin.");

        CLI::Option *optLocalKeyType = parent.add_option("--keytype,-t", parameters.keyTypeAndVariant, "Type of key being decrypted.");

        /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        // IMPORTANT: NOTE ON THE TWO WAYS IN WHICH THE KEYDECRYPT COMMAND CAN BE USED
        //
        // The keydecrypt command can be used in one of two ways, or "methods":
        //
        // "Method-A (Supplied Response)"  : Parse QO keygen response string (from either a pipe or a file).
        //                                   This response string contains all transient, key-specific
        //                                   data, but not the shared secret or nonce. These must be supplied
        //                                   separately.
        //                                   This is the normal way to use keydecrypt.
        //
        // "Method-B (Pre-parsed Response)": Specify the key-specific data as separate arguments e.g. seed, counter, encrypted_data, etc
        //                                   This is extended or advanced functionality.
        //
        // The Nonce and SharedSecret args must be supplied explicitely for both Method-A and Method-B. These are "Common".
        // Similarly, the output filename is also "Common", but is optional.
        //
        // A note on CLI11 Groups:
        // We will use CLI11's "->group(name)" modifier to reflect these 2 methods in the help.
        // The groups themselves make no functional difference - they only affect the grouping in the help text.
        // However, the excludes() and needs() rules below most certainly do make a difference, and are enforced.
        /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

        // Method-A (Supplied Response): Parse QO keygen response string (from either a pipe or a file).
        optKeyDecryptInputFilename->group("Method-A (Supplied Response)")
            ->excludes(optKeyDecryptCipherTextSeedFormat)
            ->excludes(optKeyDecryptCipherTextSeed)
            ->excludes(optKeyDecryptCipherTextNewKeyFormat)
            ->excludes(optKeyDecryptCipherTextNewKey)
            ->excludes(optKeyDecryptCipherTextCounter);

        // Method-B (Pre-parsed Response): Specify the key-specific data as separate arguments e.g. seed, counter, encrypted_data, etc
        optKeyDecryptCipherTextSeedFormat->group("Method-B (Pre-parsed Response)")
            ->needs(optKeyDecryptCipherTextSeed)
            ->needs(optKeyDecryptCipherTextNewKey)
            ->excludes(optKeyDecryptInputFilename);
        optKeyDecryptCipherTextSeed->group("Method-B (Pre-parsed Response)")->needs(optKeyDecryptCipherTextNewKey)->excludes(optKeyDecryptInputFilename);
        optKeyDecryptCipherTextNewKeyFormat->group("Method-B (Pre-parsed Response)")
            ->needs(optKeyDecryptCipherTextNewKey)
            ->needs(optKeyDecryptCipherTextSeed)
            ->excludes(optKeyDecryptInputFilename);
        optKeyDecryptCipherTextNewKey->group("Method-B (Pre-parsed Response)")->needs(optKeyDecryptCipherTextSeed)->excludes(optKeyDecryptInputFilename);
        optKeyDecryptCipherTextCounter->group("Method-B (Pre-parsed Response)")
            ->needs(optKeyDecryptCipherTextNewKey)
            ->needs(optKeyDecryptCipherTextSeed)
            ->excludes(optKeyDecryptInputFilename);

        // Validation and Transformation Rules
        optKeyDecryptCipherTextSeedFormat->transform(CLI::CheckedTransformer(dataFormatMap, CLI::ignore_case));
        optKeyDecryptCipherTextNewKeyFormat->transform(CLI::CheckedTransformer(dataFormatMap, CLI::ignore_case));
        optLocalKeyType->transform(CLI::CheckedTransformer(supportedKeyTypes, CLI::ignore_case));

        optKeyDecryptCipherTextSeed->transform(transformFilenameToValue);
        optKeyDecryptCipherTextNewKey->transform(transformFilenameToValue);

        parent.callback(
            [&]()
            {
                // Parse the string/format pairs into byte vectors
                parameters.seed            = seedDataParameter.getData();
                parameters.encryptedNewKey = encryptedNewKeyDataParameter.getData();
            });
    }

} // namespace Quantinuum::QuantumOrigin::Cli::Commands::Decrypt
