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
#include "parameters.h"

#include "boost/date_time/gregorian/gregorian.hpp"
#include <magic_enum.hpp>
#include <spdlog/fmt/bin_to_hex.h>
#include <spdlog/spdlog.h>

namespace Quantinuum::QuantumOrigin::Cli::Commands::Usage
{
    using namespace boost::gregorian;
    const std::unordered_map<std::string, Common::UsageQuery> usageQueryMap{
        {          "KEY-TYPE",           Common::UsageQuery::KEY_TYPE},
        {             "MONTH",              Common::UsageQuery::MONTH},
        {"MONTH-AND-KEY-TYPE", Common::UsageQuery::MONTH_AND_KEY_TYPE},
        {             "TOTAL",              Common::UsageQuery::TOTAL},
    };

    void UsageParameters::print() const
    {
        spdlog::debug("cert                  = \"{}\"", apiParameters.authParameters.clientCertificateFilename);
        spdlog::debug("privateKeyForCert     = \"{}\"", apiParameters.authParameters.privateKeyFilename);
        spdlog::debug("url                   = \"{}\"", apiParameters.url);
        spdlog::debug("ApiKey                = \"{}\"", apiParameters.authParameters.apiKey);
        spdlog::debug("ClientID              = \"{}\"", apiParameters.authParameters.clientId);
        spdlog::debug("to                    = \"{}\"", to);
        spdlog::debug("from                  = \"{}\"", from);
        spdlog::debug("group by              = \"{}\"", magic_enum::enum_name(groupBy));
        spdlog::debug("outputFilename        = \"{}\"", outputParameters.outputFilename);
    }

    bool UsageParameters::invalidTimeOrder() const
    {
        date dateFrom(from_simple_string(from));
        date dateTo(from_simple_string(to));
        return dateFrom > dateTo;
    }

} // namespace Quantinuum::QuantumOrigin::Cli::Commands::Usage
