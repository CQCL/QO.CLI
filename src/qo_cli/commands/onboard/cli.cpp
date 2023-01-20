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

namespace Quantinuum::QuantumOrigin::Cli::Commands::Onboard
{

    OnboardCliCommand::OnboardCliCommand() : CliCommand("onboard", "Perform onboarding.", {"ob"}) {}

    void OnboardCliCommand::addParameters(CLI::App &parent, OnboardParameters &parameters)
    {
        CLI::Option *optOnboardTargetURL =
            parent.add_option("--url,-u", parameters.apiParameters.url, "URL of server to perform onboarding. Mandatory.")->envname("QO_URL");
        CLI::Option *optOnboardApiKey =
            parent.add_option("--api-key,-a", parameters.apiParameters.authParameters.apiKey, "The API key used in the header of the request. Mandatory.");
        CLI::Option *optOnboardSecret = parent.add_option("--secret,-s", parameters.onboardingAuth, "Onboarding authentication secret. Mandatory.")->required();
    }

} // namespace Quantinuum::QuantumOrigin::Cli::Commands::Onboard
