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
#pragma once

#include "cli.h"
#include "command_base.hpp"
#include "config.h"
#include "parameters.h"

namespace Quantinuum::QuantumOrigin::Cli::Commands::RandomnessApi
{

    class RandomnessApiCommand : public CommandBase<RandomnessApiParameters, RandomnessApiCliCommand, RandomnessApiConfig>
    {
      public:
        void useConfigParameters() override;
        void checkParameters() override;
        void execute() override;
    };

} // namespace Quantinuum::QuantumOrigin::Cli::Commands::RandomnessApi
