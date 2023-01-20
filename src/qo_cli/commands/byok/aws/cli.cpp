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
#include <spdlog/spdlog.h>

namespace Quantinuum::QuantumOrigin::Cli::Commands::Byok::Aws
{

    ByokAwsCliCommand::ByokAwsCliCommand() : CliCommand("aws", "Key management system for AWS") {}

    void ByokAwsCliCommand::addParameters(CLI::App &parent, ByokAwsParameters &parameters)
    {
        ////////////////////////////////////
        // Options for Command: Kms
        ////////////////////////////////////
        CLI::Option *optKmsAlias       = parent.add_option("--alias,-a", parameters.alias, "Alias of the key. Default sets no alias");
        CLI::Option *optKmsDescription = parent.add_option("--describe,-m", parameters.description, "Description of the key. Default sets to blank");
        CLI::Option *optKmsExpiryDate =
            parent.add_option("--expiry", parameters.expiryDate, "The expiry date in ISO_8601 format. e.g \"2020-05-21T15:16:43Z\" . Default sets key to not expire");
        CLI::Option *optKmsProfile = parent.add_option("--profile,-p", parameters.profile, "Which AWS profile to use. Default is profile=[default]");

        optKmsAlias->group("Aws");
        optKmsDescription->group("Aws");
        optKmsExpiryDate->group("Aws");
        optKmsProfile->group("Aws");
    }

} // namespace Quantinuum::QuantumOrigin::Cli::Commands::Byok::Aws
