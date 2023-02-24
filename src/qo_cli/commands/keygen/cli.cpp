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
#include "command_base.hpp"
#include "parameters.h"

#include <CLI/CLI.hpp>

namespace Quantinuum::QuantumOrigin::Cli::Commands::Keygen
{

    KeygenCliCommand::KeygenCliCommand() : CliCommand("keygen", "Generate a new key.", {"kg"}) {}

    void KeygenCliCommand::addParameters(CLI::App &parent, KeygenParameters &parameters)
    {
        parameters.apiParameters.addParametersToCli(parent);
        parameters.decryptionParameters.addParametersToCli(parent);
        parameters.outputParameters.addParametersToCli(parent);

        ////////////////////////////////////
        // Options for Command: KeyGen
        ////////////////////////////////////
        CLI::Option *optKeygenKeyType       = parent.add_option("--keytype,-t", parameters.keyType, "Key Requested. Mandatory if -a not set.");
        CLI::Option *optKeygenKeyAlgorithm  = parent.add_option("--keyalg,-a", parameters.keyAlgorithm, "Type of key requested. Mandatory if -t not set.");
        CLI::Option *optKeygenKeyParameters = parent.add_option("--keyparameters,-p", parameters.keyParameters.json, "The key's parameters as JSON. Mandatory if -a set");

        optKeygenKeyType->group("KeyGen");
        optKeygenKeyParameters->group("KeyGen");
        optKeygenKeyAlgorithm->group("KeyGen");
        optKeygenKeyAlgorithm->transform(CLI::CheckedTransformer(keyAlgorithmMap, CLI::ignore_case));
    }

} // namespace Quantinuum::QuantumOrigin::Cli::Commands::Keygen
