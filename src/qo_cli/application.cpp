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
#include "application.h"
#include "command_base.hpp"
#include "config.h"
#include "qo_cli/version.h"

#ifdef INCLUDE_SUPPORT_FOR_KEYGEN
#include "commands/keygen/command.h"
#endif // INCLUDE_SUPPORT_FOR_KEYGEN

#ifdef INCLUDE_SUPPORT_FOR_KEYDECRYPT
#include "commands/decrypt/command.h"
#include <qo_decrypt/qo_crypto_aes_gcm.h>
#endif // INCLUDE_SUPPORT_FOR_KEYDECRYPT

#ifdef INCLUDE_SUPPORT_FOR_ONBOARD
#include "commands/onboard/command.h"
#endif // INCLUDE_SUPPORT_FOR_ONBOARD

#ifdef INCLUDE_SUPPORT_FOR_RANDOMNESS_API
#include "commands/randomness_api/command.h"
#endif // INCLUDE_SUPPORT_FOR_RANDOMNESS_API



#ifdef INCLUDE_SUPPORT_FOR_KMS
#include "commands/byok/command.h"
#endif

#ifdef INCLUDE_SUPPORT_FOR_USAGE
#include "commands/usage/command.h"
#endif

#include <fmt/format.h>

#include <memory>
#include <vector>

namespace Quantinuum::QuantumOrigin::Cli
{

    Application::Application() : cliApp(QO_CLI_PROGRAMNAME_LONG, QO_CLI_PROGRAMID) {}

    void Application::run(int argc, char **argv)
    {
        std::vector<std::string> args;

        for (unsigned int i = 0; i < argc; ++i)
        {
            args.emplace_back(argv[i]);
        }

        run(args);
    }

    void Application::addSupportedSubcommands()
    {
#ifdef INCLUDE_SUPPORT_FOR_KEYGEN
        commands.push_back(std::make_unique<Commands::Keygen::KeygenCommand>());
#endif // INCLUDE_SUPPORT_FOR_KEYGEN
#ifdef INCLUDE_SUPPORT_FOR_KEYDECRYPT
        commands.push_back(std::make_unique<Commands::Decrypt::DecryptCommand>());
#endif // INCLUDE_SUPPORT_FOR_KEYDECRYPT
#ifdef INCLUDE_SUPPORT_FOR_ONBOARD
        commands.push_back(std::make_unique<Commands::Onboard::OnboardCommand>());
#endif // INCLUDE_SUPPORT_FOR_ONBOARD
#ifdef INCLUDE_SUPPORT_FOR_RANDOMNESS_API
        commands.push_back(std::make_unique<Commands::RandomnessApi::RandomnessApiCommand>());
#endif // INCLUDE_SUPPORT_FOR_RANDOMNESS_API
#ifdef INCLUDE_SUPPORT_FOR_KMS
        commands.push_back(std::make_unique<Commands::Byok::ByokCommand>());
#endif // INCLUDE_SUPPORT_FOR_KMS
#ifdef INCLUDE_SUPPORT_FOR_USAGE
        commands.push_back(std::make_unique<Commands::Usage::UsageCommand>());
#endif // INCLUDE_SUPPORT_FOR_USAGE
    }

    void Application::run(std::vector<std::string> &args)
    {
        initParser();
        addGlobalParameters();
        addSupportedSubcommands();

        for (auto &command : commands)
        {
            command->addSubcommandAndParameters(cliApp);
        }

        // The CLI11 parse function which takes a std::vector<std::string> expects it to be reversed
        std::reverse(args.begin(), args.end());
        cliApp.parse(args);

        if (parameters.configFile)
        {
            CliConfig config(*parameters.configFile);
            const auto &configLogLevel = config.getGeneralConfig().getLevel();
            if (configLogLevel)
            {
                // If a logging level was supplied in the config, set logging appropriately
                spdlog::set_level(*configLogLevel);
            }
        };

        // Adjust the log level based on the parameter that was passed, otherwise leave alone
        // Overrides any log-level that may have been set from the config above
        if (parameters.logLevel)
        {
            spdlog::set_level(*parameters.logLevel);
        }

        spdlog::info(QO_CLI_PROGRAMNAME_LONG);
        spdlog::debug("Command line arguments parsed successfully");

        for (auto &command : commands)
        {
            if (*command)
            {
                if (parameters.configFile)
                {
                    command->loadConfig(*parameters.configFile);
                };

                // Print the parameters for debug purposes
                command->printParams();

                spdlog::trace("Running {} subcommand", command->getCommandName());
                command->executeCommand();
            }
        }
    }

    void Application::addGlobalParameters()
    {
        cliApp.add_option("--config", parameters.configFile, "Location on config .yml file");
        cliApp.add_option("-l,--log", parameters.logLevel, "Level of logging to use. Default: info")->transform(CLI::CheckedTransformer(logLevelMap, CLI::ignore_case));
    }

    void Application::initParser()
    {
        ////////////////////////////////////
        // Flags affecting all commands
        ////////////////////////////////////

        // Allow unmatched arguments on subcommands to fall back to matching on the parent command
        cliApp.fallthrough(true);

        cliApp.allow_windows_style_options();
        cliApp.allow_extras();

#ifdef INCLUDE_SUPPORT_FOR_KEYDECRYPT
        std::string version_string = fmt::format("{} {} [Decrypt Lib {}]", QO_CLI_PROGRAMID, QO_CLI_VERSION_STRING, qo_decrypt_version());
#else
        std::string version_string = fmt::format("{} {}", QO_CLI_PROGRAMID, QO_CLI_VERSION_STRING);
#endif

        cliApp.set_version_flag("--version", version_string);
        cliApp.set_help_flag("--help,-h", "Print this help message and exit (see also --help-all)");
        cliApp.set_help_all_flag("--help-all,-H", "Display help for all commands & options");

        // myApp.get_formatter()->column_width(92);
        cliApp.get_formatter()->column_width(12);
        cliApp.get_formatter()->label("REQUIRED", "REQD");

        ////////////////////////////////////
        // Commands
        ////////////////////////////////////
        cliApp.require_subcommand(1, 1); // (min,max) i.e. Exactly 1
    }

    int Application::exit(const CLI::Error &e)
    {
        return cliApp.exit(e);
    }

} // namespace Quantinuum::QuantumOrigin::Cli
