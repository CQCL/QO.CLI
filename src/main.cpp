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
///////////////////////////////////////////////////////////////////////////////
// Quantum Origin Client-Side CLI

// Command line tool that deciphers a keygen response received from the Quantum
// Origin Restful API, either with individual parameters, or output piped from curl
// and then piped out to a file or other shell utility.Internally it will gather
// all the required data from command-line parameters, stdin input stream, config
// files etc. and ultimately call the C Library:
///////////////////////////////////////////////////////////////////////////////

#include "qo_cli/application.h"

#include <CLI/CLI.hpp>
#include <spdlog/spdlog.h>

#include <cstdlib>
#include <stdexcept>

int main(int argc, char *argv[])
{
    // Default log-level
    spdlog::set_level(spdlog::level::level_enum::info);

    // Uncomment to enable trace logging during parsing, before the logging argument is actioned
    // spdlog::set_level(spdlog::level::trace);

    Quantinuum::QuantumOrigin::Cli::Application app;
    try
    {
        app.run(argc, argv);
    }
    catch (const CLI::Error &ex)
    {
        return app.exit(ex);
    }
    catch (const std::exception &ex)
    {
        spdlog::error("Exception: {}", ex.what());
        return EXIT_FAILURE;
    }
    catch (...)
    {
        spdlog::error("Unknown exception thrown!");
        return EXIT_FAILURE;
    }

    spdlog::info("Done");

    return EXIT_SUCCESS;
}
