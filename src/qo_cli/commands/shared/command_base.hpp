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

#include <CLI/CLI.hpp>

#include <concepts>
#include <optional>
#include <string>
#include <vector>

namespace Quantinuum::QuantumOrigin::Cli::Commands
{

    /**
     * Base-class representing a CLI subcommand
     *
     * @tparam P The type that contains the subcommand parameters
     */
    template <typename P>
    class CliCommand
    {
      public:
        virtual ~CliCommand() = default;

        CliCommand(std::string command, std::string description, std::vector<std::string> aliases = {})
            : command(std::move(command)), description(std::move(description)), aliases(std::move(aliases))
        {
        }

        virtual CLI::App *addSubcommand(CLI::App &parent)
        {
            subcommand = parent.add_subcommand(command, description);

            for (const auto &alias : aliases)
            {
                subcommand->alias(alias);
            }

            return subcommand;
        }

        virtual void addParameters(CLI::App &parent, P &parameters) = 0;

        virtual CLI::App *addSubcommandAndParameters(CLI::App &parent, P &parameters) final
        {
            addSubcommand(parent);
            addParameters(*subcommand, parameters);

            return subcommand;
        }

        explicit operator bool() const
        {
            return subcommand && *subcommand;
        }

        [[nodiscard]] const std::string &getCommandName() const
        {
            return command;
        }

      private:
        std::string command;
        std::string description;
        std::vector<std::string> aliases;

      protected:
        CLI::App *subcommand = nullptr;
    };

    std::string transformFilenameToValue(const std::string &inString);

    /**
     * Shared interface to all subcommands
     */
    class ICommand
    {
      public:
        virtual ~ICommand() = default;

        /**
         * @brief Adds the commands to a parent CLI11 parser
         * @param parent The CLI11 parent parser/app
         */
        virtual void addSubcommandAndParameters(CLI::App &parent) = 0;

        /**
         * @brief Executes the command
         */
        virtual void executeCommand() = 0;

        /**
         * @brief Gets the name of the command
         * @return The command name
         */
        [[nodiscard]] virtual const std::string &getCommandName() const = 0;

        /**
         * @brief Loads the config file for this command
         * @param configFile Path to the config file
         */
        virtual void loadConfig(const std::string &configFile) = 0;

        /**
         * @brief Converts to a boolean representing whether this command was chosen
         * @return True is parser has run and the user chose this command, false otherwise
         */
        virtual explicit operator bool() const = 0;

        /**
         * @brief Prints out all the command parameters
         */
        virtual void printParams() const = 0;

      protected:
        /**
         * @brief Checks the commands parameters.
         *
         * Each command should implement this to check all its required parameters are present.
         * This is used instead of the 'required()' function on the CLI parameters, because a
         * required parameter might not be provided on the command-line, and could be provided
         * in the config file instead.
         */
        virtual void checkParameters() = 0;

        /**
         * Each command should implement this function to use the config to fill in any parameters
         * that are given in the config file but were not provided on the command-line.
         */
        virtual void useConfigParameters() = 0;

        /**
         * Each command should implement this function to execute its specific action.
         */
        virtual void execute() = 0;
    };

    /**
     * Concept that ensures that a specific type is derived from the IParameters base-type
     * @tparam T The type to check
     */
    template <typename T>
    concept ParamType = std::derived_from<T, IParameters>;

    /**
     * Concept that ensures a specific type is derived from the CliCommand base-type
     * @tparam T The type to check
     * @tparam ParamType The parameter-type that the CliCommand class is templated on
     */
    template <typename T, typename ParamType>
    concept CliType = std::derived_from<T, CliCommand<ParamType>>;

    /**
     * Base-class for all commands, provides default implementations for some parts of the ICommand interface
     *
     * @tparam Params The type representing the parameters for the command
     * @tparam Cli The type representing the CLI subcommand
     * @tparam Config The type representing the config file for the command
     */
    template <ParamType Params, CliType<Params> Cli, typename Config>
    class CommandBase : public ICommand
    {
      public:
        CommandBase() = default;

        template <ParamType ParentParams>
        explicit CommandBase(const ParentParams &parentParams) : parameters(parentParams)
        {
        }

        void addSubcommandAndParameters(CLI::App &parent) override
        {
            // Add this subcommand
            auto addedSubcommand = cliCommand.addSubcommandAndParameters(parent, parameters);

            for (auto &subCommand : subCommands)
            {
                // Also add any subcommands of this subcommand, with this command as their parent
                subCommand->addSubcommandAndParameters(*addedSubcommand);
            }
        }

        explicit operator bool() const override
        {
            return static_cast<bool>(cliCommand);
        }

        [[nodiscard]] const std::string &getCommandName() const override
        {
            return cliCommand.getCommandName();
        }

        void loadConfig(const std::string &configFile) override
        {
            // Load the config for the chosen command
            config = Config(configFile);
            // Use the config parameters to fill in any values that weren't given on the command-line
            useConfigParameters();

            for (auto &subCommand : subCommands)
            {
                if (*subCommand)
                {
                    // Also load the config into any chosen subcommands
                    subCommand->loadConfig(configFile);
                }
            }
        }

        void executeCommand() override
        {
            // Check all the required parameters are present
            checkParameters();

            for (auto &subCommand : subCommands)
            {
                if (*subCommand)
                {
                    // If we have a subcommand, execute that (which will also check its parameters)
                    subCommand->executeCommand();
                    return;
                }
            }

            // If there were not subcommands, execute this command
            execute();
        }

        void printParams() const override
        {
            // Print out the specified parameters for debug purposes
            parameters.print();

            for (auto &subCommand : subCommands)
            {
                if (*subCommand)
                {
                    // Also print the parameters for any chosen subcommands
                    subCommand->printParams();
                }
            }
        }

      protected:
        Params &getParameters()
        {
            return parameters;
        }

        const Params &getParameters() const
        {
            return parameters;
        }

        const std::optional<Config> &getConfig() const
        {
            return config;
        }

        void addNewSubcommand(std::unique_ptr<Commands::ICommand> subCommand)
        {
            subCommands.push_back(std::move(subCommand));
        }

      private:
        Cli cliCommand;
        Params parameters;
        std::optional<Config> config;

        std::vector<std::unique_ptr<Commands::ICommand>> subCommands;
    };

    enum class DataFormat
    {
        Base64,
        Hex,
        Ascii,
        Binary,
    };

    extern const std::unordered_map<std::string, DataFormat> dataFormatMap;

    std::string to_string(const DataFormat &x);

    class DataParseError : public std::runtime_error
    {
      public:
        explicit DataParseError(const std::exception &ex, DataFormat format = DataFormat::Base64, std::string name = "parameter");
    };

    /**
     * Class used to encapsulate the parsing of data parameters, which are binary data that can be represented in a variety of encoding formats.
     */
    class DataParameter
    {
      public:
        explicit DataParameter(std::string name = "parameter");
        explicit DataParameter(DataFormat defaultFormat, std::string name = "parameter");
        explicit DataParameter(std::vector<uint8_t> data, std::string name = "parameter");
        explicit DataParameter(std::string data, DataFormat format, std::string name = "parameter");

        DataFormat &getFormat();
        std::string &getDataString();

        void parse();
        const std::vector<uint8_t> &getData();

      private:
        std::string name;
        DataFormat format = DataFormat::Base64;
        std::string dataString;

        std::optional<std::vector<uint8_t>> data;
    };

    class MissingParameterError : public std::runtime_error
    {
      public:
        explicit MissingParameterError(const std::string &parameterName);
    };

} // namespace Quantinuum::QuantumOrigin::Cli::Commands
