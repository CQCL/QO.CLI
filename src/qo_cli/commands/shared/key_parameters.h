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

#include <string>
#include <unordered_map>
#include <utility>

namespace Quantinuum::QuantumOrigin::Cli
{

    enum class CliLocal_Key_Type
    {
        KEY_TYPE_UNKNOWN = 0,
        KEY_TYPE_AES,
        KEY_TYPE_RSA,
        KEY_TYPE_EC,
        KEY_TYPE_PQ_SIG,
        KEY_TYPE_PQ_KEM,
        KEY_TYPE_RAND,
    };

    /// The type of AES key to be generated
    ///
    /// Corresponds with the key size in bits
    enum CliLocal_AES_Variant
    {
        AES_128 = 128,
        AES_192 = 192,
        AES_256 = 256,
    };

    /// The curve on which an EC key should be generated
    enum CliLocal_EC_Variant
    {
        BP256R1,
        BP384R1,
        BP512R1,
        SECP192K1,
        SECP192R1,
        SECP224K1,
        SECP224R1,
        SECP256K1,
        SECP256R1,
        SECP384R1,
        SECP521R1,
        X25519,
    };

    /// The type of RSA key to be generated
    ///
    /// Corresponds with the key size in bits
    enum CliLocal_RSA_Variant
    {
        RSA_2048 = 2048,
        RSA_3072 = 3072,
        RSA_4096 = 4096,
    };

    /// The type of post-quantum signature key to be generated
    enum CliLocal_PQ_Signature_Variant
    {
        SIG_DILITHIUM2,
        SIG_DILITHIUM3,
        SIG_DILITHIUM5,
        SIG_DILITHIUM2_AES,
        SIG_DILITHIUM3_AES,
        SIG_DILITHIUM5_AES,
        SIG_RAINBOW_I_CLASSIC,
        SIG_RAINBOW_I_CIRCUMZENITHAL,
        SIG_RAINBOW_I_COMPRESSED,
        SIG_RAINBOW_III_CLASSIC,
        SIG_RAINBOW_III_CIRCUMZENITHAL,
        SIG_RAINBOW_III_COMPRESSED,
        SIG_RAINBOW_V_CLASSIC,
        SIG_RAINBOW_V_CIRCUMZENITHAL,
        SIG_RAINBOW_V_COMPRESSED,
        SIG_FALCON_512,
        SIG_FALCON_1024,
        SIG_SPHINCS_HARAKA_128F_ROBUST,
        SIG_SPHINCS_HARAKA_128F_SIMPLE,
        SIG_SPHINCS_HARAKA_128S_ROBUST,
        SIG_SPHINCS_HARAKA_128S_SIMPLE,
        SIG_SPHINCS_HARAKA_192F_ROBUST,
        SIG_SPHINCS_HARAKA_192F_SIMPLE,
        SIG_SPHINCS_HARAKA_192S_ROBUST,
        SIG_SPHINCS_HARAKA_192S_SIMPLE,
        SIG_SPHINCS_HARAKA_256F_ROBUST,
        SIG_SPHINCS_HARAKA_256F_SIMPLE,
        SIG_SPHINCS_HARAKA_256S_ROBUST,
        SIG_SPHINCS_HARAKA_256S_SIMPLE,
        SIG_SPHINCS_SHA256_128F_ROBUST,
        SIG_SPHINCS_SHA256_128F_SIMPLE,
        SIG_SPHINCS_SHA256_128S_ROBUST,
        SIG_SPHINCS_SHA256_128S_SIMPLE,
        SIG_SPHINCS_SHA256_192F_ROBUST,
        SIG_SPHINCS_SHA256_192F_SIMPLE,
        SIG_SPHINCS_SHA256_192S_ROBUST,
        SIG_SPHINCS_SHA256_192S_SIMPLE,
        SIG_SPHINCS_SHA256_256F_ROBUST,
        SIG_SPHINCS_SHA256_256F_SIMPLE,
        SIG_SPHINCS_SHA256_256S_ROBUST,
        SIG_SPHINCS_SHA256_256S_SIMPLE,
        SIG_SPHINCS_SHAKE256_128F_ROBUST,
        SIG_SPHINCS_SHAKE256_128F_SIMPLE,
        SIG_SPHINCS_SHAKE256_128S_ROBUST,
        SIG_SPHINCS_SHAKE256_128S_SIMPLE,
        SIG_SPHINCS_SHAKE256_192F_ROBUST,
        SIG_SPHINCS_SHAKE256_192F_SIMPLE,
        SIG_SPHINCS_SHAKE256_192S_ROBUST,
        SIG_SPHINCS_SHAKE256_192S_SIMPLE,
        SIG_SPHINCS_SHAKE256_256F_ROBUST,
        SIG_SPHINCS_SHAKE256_256F_SIMPLE,
        SIG_SPHINCS_SHAKE256_256S_ROBUST,
        SIG_SPHINCS_SHAKE256_256S_SIMPLE,
    };

    /// The type of post-quantum KEM key to be generated
    enum CliLocal_PQ_KEM_Variant
    {
        KEM_LIGHTSABER,
        KEM_FIRESABER,
        KEM_SABER,
        KEM_MCELIECE_348864,
        KEM_MCELIECE_348864F,
        KEM_MCELIECE_460896,
        KEM_MCELIECE_460896F,
        KEM_MCELIECE_6688128,
        KEM_MCELIECE_6688128F,
        KEM_MCELIECE_6960119,
        KEM_MCELIECE_6960119F,
        KEM_MCELIECE_8192128,
        KEM_MCELIECE_8192128F,
        KEM_KYBER_512,
        KEM_KYBER_512_90S,
        KEM_KYBER_1024,
        KEM_KYBER_1024_90S,
        KEM_KYBER_768,
        KEM_KYBER_768_90S,
        KEM_NTRU_2048_509,
        KEM_NTRU_2048_677,
        KEM_NTRU_4096_821,
        KEM_NTRU_HRSS_701,
        KEM_NTRULPR_653,
        KEM_NTRULPR_761,
        KEM_NTRULPR_857,
        KEM_NTRULPR_1277,
        KEM_SNTRUP_653,
        KEM_SNTRUP_761,
        KEM_SNTRUP_857,
        KEM_SNTRUP_1277,
        KEM_HQC_128,
        KEM_HQC_192,
        KEM_HQC_256,
        KEM_BIKE_L1,
        KEM_BIKE_L3,
    };

    class KeyTypeAndVariant
    {
      public:
        CliLocal_Key_Type keyType;
        int variant;

        bool operator==(const KeyTypeAndVariant &other) const
        {
            return this->keyType == other.keyType && this->variant == other.variant;
        }
    };

    bool lexical_cast(const std::string &input, KeyTypeAndVariant &output);
    extern const std::unordered_map<std::string, KeyTypeAndVariant> supportedKeyTypes;
    KeyTypeAndVariant parseKeyTypeAndVariantString(std::string keyTypeString);
    Commands::OutputFormat defaultOutputFormat(const std::optional<KeyTypeAndVariant> &keyTypeAndVariant = std::nullopt);

} // namespace Quantinuum::QuantumOrigin::Cli
