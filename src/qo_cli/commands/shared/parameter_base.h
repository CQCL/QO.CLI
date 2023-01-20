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

#include <CLI/CLI.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace Quantinuum::QuantumOrigin::Cli::Commands
{

    class IParameters
    {
      public:
        virtual void print() const = 0;
    };

    enum class OutputFormat
    {
        Pem,
        Jwk,
        Base64,
        Hex,
        Binary,
        None,
    };

    extern const std::unordered_map<std::string, OutputFormat> outputFormatMap;

    /**
     * Represents the parameters used to output some result, either to a file or to the screen
     */
    class OutputParameters
    {
      public:
        std::optional<OutputFormat> outputFormat;
        std::string outputFilename;

        void addParametersToCli(CLI::App &parent, std::optional<std::vector<std::string>> allowed = std::nullopt);
        std::ostream &getOutputStream();

      private:
        std::unique_ptr<std::ostream> outputStream;
    };

} // namespace Quantinuum::QuantumOrigin::Cli::Commands
