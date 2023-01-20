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

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pk.h>
#include <qo_common/service.h>

#include <optional>
#include <string>

class CliOnboard
{
  private:
    Quantinuum::QuantumOrigin::Common::Connection connection;
    mbedtls_pk_context _userKey;
    mbedtls_ctr_drbg_context _drbgCtx;
    mbedtls_entropy_context _entropyCtx;

    void GenerateUserKey();
    size_t CheckMbedRV(int, const std::string &);

  public:
    // If a key file is provided it will be loaded, otherwise a new key will be generated
    CliOnboard(std::string url, const std::string &apiKey, const std::string &onboardAuth, std::optional<std::string> userKeyFile = std::nullopt);
    ~CliOnboard();

    void Onboard(int connectionAttempts = 3);
    std::vector<uint8_t> DecryptECDH(const mbedtls_pk_context &serverKey, const std::vector<uint8_t> &encryptedSecret);
};
