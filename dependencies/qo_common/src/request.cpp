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
#include "qo_common/request.h"

namespace Quantinuum::QuantumOrigin::Common
{

    Request::Request(std::string endpoint, httpMethod method) : _endpoint(std::move(endpoint)), _method(method) {}

    const std::string &Request::getEndpoint() const
    {
        return _endpoint;
    }

    const httpMethod &Request::getMethod() const
    {
        return _method;
    }

    CryptoRequest::CryptoRequest(std::string endpoint, std::vector<uint8_t> nonce, EncryptionSchemeEnum encryptionScheme)
        : Request(std::move(endpoint), httpMethod::POST), _nonces({std::move(nonce)}), _encryptionScheme(encryptionScheme)
    {
    }

    CryptoRequest::CryptoRequest(std::string endpoint, std::vector<std::vector<uint8_t>> nonces, EncryptionSchemeEnum encryptionScheme)
        : Request(std::move(endpoint), httpMethod::POST), _nonces(std::move(nonces)), _encryptionScheme(encryptionScheme)
    {
    }

} // namespace Quantinuum::QuantumOrigin::Common
