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

#define MAX_NOF_BYTES_FROM_API (2 * 1024 * 1024)

namespace Quantinuum::QuantumOrigin::Cli::Commands::RandomnessApi
{

    RandomnessApiCliCommand::RandomnessApiCliCommand() : CliCommand("randomness", "Retrieve randomness from QO API", {"ra"}) {}

    void RandomnessApiCliCommand::addParameters(CLI::App &parent, RandomnessApiParameters &parameters)
    {
        parameters.apiParameters.addParametersToCli(parent);
        parameters.decryptionParameters.addParametersToCli(parent);
        parameters.outputParameters.addParametersToCli(
            parent, std::vector<OutputFormat>{OutputFormat::Base64, OutputFormat::Hex, OutputFormat::Binary}); // pem/jwk wouldn't make sense for randomness

        CLI::Option *optRandomnessSize = parent.add_option("randSize", parameters.randSize, "Number of bytes of randomness. Default = 128.")->default_val(128);

        optRandomnessSize->check(CLI::Range(1, MAX_NOF_BYTES_FROM_API)); // API has a max nof bytes that can be requested
        optRandomnessSize->group("Randomness");
    }

} // namespace Quantinuum::QuantumOrigin::Cli::Commands::RandomnessApi
