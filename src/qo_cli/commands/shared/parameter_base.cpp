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
#include "parameter_base.h"

#include <CLI/CLI.hpp>
#include <boost/iostreams/device/null.hpp>
#include <boost/iostreams/stream.hpp>
#include <spdlog/spdlog.h>

#include <stdexcept>

namespace Quantinuum::QuantumOrigin::Cli::Commands
{

    const std::unordered_map<std::string, OutputFormat> outputFormatMap{
        {   "pem",    OutputFormat::Pem},
        {   "jwk",    OutputFormat::Jwk},
        {"base64", OutputFormat::Base64},
        {   "hex",    OutputFormat::Hex},
        {   "raw", OutputFormat::Binary},
        {  "none",   OutputFormat::None},
    };

    void OutputParameters::addParametersToCli(CLI::App &parent, std::optional<std::vector<OutputFormat>> allowed)
    {
        CLI::Option *optOutputFormat = parent.add_option(
            "--outputformat,-O", outputFormat,
            "Format of the output. Default=base64 for AES or randomness, pem for RSA and EC, jwk for PQC KEM and signing keys. Optional.");
        CLI::Option *optOutputFilename =
            parent.add_option("--outputfile,-o", outputFilename, "Filename of where to write the output. Optional. Use 'stdout' to print to screen.");

        optOutputFormat->group("Output");
        optOutputFilename->group("Output");

        if (allowed)
        {
            optOutputFormat->check(CLI::IsMember(*allowed));
        }

        optOutputFormat->transform(CLI::CheckedTransformer(outputFormatMap, CLI::ignore_case));
    }

    std::ostream &OutputParameters::getOutputStream()
    {
        spdlog::trace("DEBUG: Output will be written to \"{}\"", outputFilename.c_str());

        if (outputFilename == "stdout")
        {
            return std::cout;
        }
        else if (outputFilename == "stderr")
        {
            return std::cerr;
        }
        else if (outputFilename.length() > 0)
        {
            if (!outputStream)
            {
                outputStream = std::make_unique<std::ofstream>(outputFilename, std::ios::out | std::ios::binary);
            }

            return *outputStream;
        }

        spdlog::warn("WARNING: No output specified, result will be discarded");

        // Return a null ostream that will just swallow all data sent to it
        outputStream = std::make_unique<boost::iostreams::stream<boost::iostreams::null_sink>>(boost::iostreams::null_sink());
        return *outputStream;
    }

} // namespace Quantinuum::QuantumOrigin::Cli::Commands
