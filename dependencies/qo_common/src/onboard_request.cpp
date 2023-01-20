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
#include <cppcodec/base64_rfc4648.hpp>
#include <qo_common/onboard_request.h>

namespace Quantinuum::QuantumOrigin::Common
{
    OnboardRequest::OnboardRequest(std::string publicKey) : Request("onboard", httpMethod::POST), _publicKey(std::move(publicKey)) {}

    nlohmann::json OnboardRequest::exportPayloadAsJson() const
    {
        nlohmann::json jsonRequestPayload;
        jsonRequestPayload["onboarding_public_key"] = _publicKey;
        return jsonRequestPayload;
    }
} // namespace Quantinuum::QuantumOrigin::Common
