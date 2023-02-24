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

#include <string>

namespace Quantinuum::QuantumOrigin::Common
{

    template <typename T>
    class EnumWrapper
    {
      public:
        using Enum = T;

        EnumWrapper(T t);
        EnumWrapper(const char *s);
        EnumWrapper(const std::string &s);

        operator T() const;
        operator std::string() const;

      private:
        T _t;
    };

    enum class KeyAlgorithm
    {
        AES,
        RSA,
        EC,
        CLASSIC_MCELIECE,
        NTRU,
        KYBER,
        SABER,
        DILITHIUM,
        FALCON,
        RAINBOW,
        HQC,
        BIKE,
        NTRU_PRIME,
        SPHINCS
    };

    using KeyAlgorithmEnum = EnumWrapper<KeyAlgorithm>;

    enum class EncryptionScheme
    {
        HKDF_AES_GCM,
        AES_KW_CMAC,
    };

    using EncryptionSchemeEnum = EnumWrapper<EncryptionScheme>;

    enum class EcCurve
    {
        Bp256r1,
        Bp384r1,
        Bp512r1,
        SecP192k1,
        SecP192r1,
        SecP224k1,
        SecP224r1,
        SecP256k1,
        SecP256r1,
        SecP384r1,
        SecP521r1,
        X25519
    };

    using EcCurveEnum = EnumWrapper<EcCurve>;

    enum class OaepHashFunction
    {
        SHA_1,
        SHA_256
    };

    using OaepHashFunctionEnum = EnumWrapper<OaepHashFunction>;

    enum class UsageQuery
    {
        KEY_TYPE,
        MONTH,
        MONTH_AND_KEY_TYPE,
        TOTAL
    };

    using UsageQueryEnum = EnumWrapper<UsageQuery>;

} // namespace Quantinuum::QuantumOrigin::Common
