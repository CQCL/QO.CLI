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


#if defined(INCLUDE_SUPPORT_FOR_KEYGEN) || defined(INCLUDE_SUPPORT_FOR_RANDOMNESS_API) || defined(INCLUDE_SUPPORT_FOR_ONBOARD) || defined(INCLUDE_SUPPORT_FOR_KMS) ||    \
    defined(INCLUDE_SUPPORT_FOR_USAGE)
#include <qo_common/exceptions.h>
#include <qo_common/key_request.h>
#include <qo_common/key_response.h>
#include <qo_common/service.h>
#endif

#include <string>

namespace Quantinuum::QuantumOrigin::Cli::Utils
{
#if defined(INCLUDE_SUPPORT_FOR_KEYGEN) || defined(INCLUDE_SUPPORT_FOR_RANDOMNESS_API) || defined(INCLUDE_SUPPORT_FOR_ONBOARD) || defined(INCLUDE_SUPPORT_FOR_KMS) ||    \
    defined(INCLUDE_SUPPORT_FOR_USAGE)
    template <typename T>
    concept RequestType = std::derived_from<T, Common::Request>;

    template <RequestType R>
    typename R::Response sendRequestWithRetries(Common::Connection &connection, const R &request, int connectionAttempts = 3)
    {
        while (connectionAttempts > 0)
        {
            try
            {
                return connection.send(request);
            }
            catch (const Common::ApiError &e)
            {
                connectionAttempts--;
                if (connectionAttempts == 0)
                {
                    throw;
                }
            }
        }

        // This shouldn't ever happen
        throw std::runtime_error("Connection failed");
    }
#endif


} // namespace Quantinuum::QuantumOrigin::Cli::Utils
