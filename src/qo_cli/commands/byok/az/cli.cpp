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
#include "parameter_base.h"
#include "parameters.h"

#include <CLI/CLI.hpp>
#include <spdlog/spdlog.h>

namespace Quantinuum::QuantumOrigin::Cli::Commands::Byok::Az
{

    ByokAzCliCommand::ByokAzCliCommand() : CliCommand("az", "Key management system for AZ") {}

    void ByokAzCliCommand::addParameters(CLI::App &parent, ByokAzParameters &parameters)
    {
        parameters.outputParameters.addParametersToCli(parent);

        ////////////////////////////////////
        // Options for Command: Kms
        ////////////////////////////////////
        CLI::Option *optKmsKeyType       = parent.add_option("--keytype,-t", parameters.keyType, "Type of key requested. Mandatory.");
        CLI::Option *optKmsKeyParameters = parent.add_option("--keyparameters,-p", parameters.keyParameters.json, "The key's parameters as JSON. Mandatory.");
        CLI::Option *optKmsKeyId         = parent.add_option("--kid", parameters.kId, "The wrapping key's Id in Azure. Mandatory.");
        CLI::Option *optKmsPemFileName =
            parent.add_option("--inkey", parameters.pemFileName, "Wrapping key generated in Azure. Target key will be encrypted with this for importing into Azure.");

        optKmsKeyType->group("Az");
        optKmsKeyParameters->group("Az");
        optKmsKeyId->group("Az");
        optKmsPemFileName->group("Az");

        optKmsKeyType->transform(CLI::CheckedTransformer(keyTypeMap, CLI::ignore_case));
    }

} // namespace Quantinuum::QuantumOrigin::Cli::Commands::Byok::Az
