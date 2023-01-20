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

#include "parameter_base.h"

#include <spdlog/spdlog.h>

#include <optional>
#include <string>
#include <unordered_map>

namespace Quantinuum::QuantumOrigin::Cli
{

    extern const std::unordered_map<std::string, spdlog::level::level_enum> logLevelMap;

    class CliParameters
    {
      public:
        std::optional<std::string> configFile;
        std::optional<spdlog::level::level_enum> logLevel;
    };

} // namespace Quantinuum::QuantumOrigin::Cli
