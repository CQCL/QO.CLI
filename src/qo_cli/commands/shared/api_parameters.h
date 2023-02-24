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

#include <qo_common/parameters.h>

#include <CLI/CLI.hpp>

#include <string>
#include <unordered_map>

namespace Quantinuum::QuantumOrigin::Cli::Commands
{

    extern const std::unordered_map<std::string, Common::KeyAlgorithm> keyAlgorithmMap;

    /**
     * Represents the parameters required for authentication to the QO API
     */
    class AuthParameters
    {
      public:
        ~AuthParameters();

        std::string clientCertificateFilename;
        std::string privateKeyFilename;

        std::string apiKey;
        std::string clientId;

        void addParametersToCli(CLI::App &parent);
    };

    /**
     * Represents the parameters required for connecting to the QO API
     */
    class ApiParameters
    {
      public:
        AuthParameters authParameters;
        std::string url;

        void addParametersToCli(CLI::App &parent);
    };

} // namespace Quantinuum::QuantumOrigin::Cli::Commands
