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
#include "onboard.h"
#include <qo_common/exceptions.h>

#include <mbedtls/asn1write.h>
#include <mbedtls/cipher.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/error.h>
#include <mbedtls/md.h>
#include <mbedtls/oid.h>

#include <cppcodec/hex_lower.hpp>
#include <spdlog/spdlog.h>

#include <array>
#include <iostream>
#include <stdexcept>

using hex = cppcodec::hex_lower;

namespace
{
    const size_t MAX_EC_SHARED_SECRET_SIZE = 66;

    struct FreeMbedtlsPk
    {
        void operator()(mbedtls_pk_context *ctx) const
        {
            // We need to use mbedtls_pk_free to free the contents of the context, then delete the context itself
            mbedtls_pk_free(ctx);
            delete (ctx);
        }
    };

    struct FreeMbedtlsEcdhCtx
    {
        void operator()(mbedtls_ecdh_context *ctx) const
        {
            // We need to use mbedtls_ecdh_free to free the contents of the context, then delete the context itself
            mbedtls_ecdh_free(ctx);
            delete (ctx);
        }
    };

    struct FreeMbedtlsCipherCtx
    {
        void operator()(mbedtls_cipher_context_t *ctx) const
        {
            // We need to use mbedtls_cipher_free to free the contents of the context, then delete the context itself
            mbedtls_cipher_free(ctx);
            delete (ctx);
        }
    };
} // namespace

CliOnboard::CliOnboard(std::string url, const std::string &apiKey, const std::string &onboardAuth, std::optional<std::string> userKeyFile)
    : connection(std::move(url)), _userKey(), _drbgCtx(), _entropyCtx()
{
    connection.addHeader(fmt::format("qo-api-key: {}", apiKey));
    connection.addHeader(fmt::format("onboarding-auth: {}", onboardAuth));
    connection.addHeader(fmt::format("qo-subscription-id: {}", apiKey));

    // Initialize drbg and platform entropy context to generate key
    mbedtls_ctr_drbg_init(&_drbgCtx);
    mbedtls_entropy_init(&_entropyCtx);
    mbedtls_ctr_drbg_seed(&_drbgCtx, mbedtls_entropy_func, &_entropyCtx, (unsigned char *)"CQC-KEY", 7);

    mbedtls_pk_init(&_userKey);

    if (userKeyFile)
    {
        CheckMbedRV(mbedtls_pk_parse_keyfile(&_userKey, userKeyFile->c_str(), nullptr, mbedtls_ctr_drbg_random, &_drbgCtx), "Failed to load public key from file");

        if (mbedtls_pk_get_type(&_userKey) == MBEDTLS_PK_ECKEY)
        {
            // TODO: Figure out how to check group, mbedtls doesn't make it easy.
            // auto group_id = mbedtls_ecp_get_type(mbedtls_pk_ec(_userKey)->mbedtls_ecp_group).mbedtls_ecp_group_id;
            // if (group_id == mbedtls_ecp_group_id::MBEDTLS_ECP_DP_SECP521R1)
        }
        else
        {
            throw std::runtime_error("Only secp521r1 keys are supported");
        }
    }
    else
    {
        GenerateUserKey();
    }
}

CliOnboard::~CliOnboard()
{
    mbedtls_entropy_free(&_entropyCtx);
    mbedtls_ctr_drbg_free(&_drbgCtx);
    mbedtls_pk_free(&_userKey);
}

void CliOnboard::Onboard(int connectionAttempts)
{
    char pk_pem[2048];
    CheckMbedRV(mbedtls_pk_write_pubkey_pem(&_userKey, (unsigned char *)pk_pem, 2048), "Failed to write out public key");

    std::string pemString(pk_pem);
    spdlog::trace("Client PEM string: {}", pemString);

    auto request = Quantinuum::QuantumOrigin::Common::OnboardRequest(pemString);
    std::vector<std::string> rawResponse;
    while (connectionAttempts > 0)
    {
        try
        {
            auto response = connection.send(request);

            spdlog::trace("Server PEM string: {}", response.transportKey);

            auto serverKey = std::unique_ptr<mbedtls_pk_context, FreeMbedtlsPk>(new mbedtls_pk_context);
            mbedtls_pk_init(serverKey.get());
            CheckMbedRV(
                mbedtls_pk_parse_public_key(serverKey.get(), reinterpret_cast<const unsigned char *>(response.transportKey.c_str()), response.transportKey.size() + 1),
                "Failed to parse server public key");

            if (mbedtls_pk_can_do(serverKey.get(), MBEDTLS_PK_ECKEY) != 1)
            {
                throw std::runtime_error("Received a key which cannot perform EC operations");
            }

            auto sharedSecret = hex::encode(DecryptECDH(*serverKey, response.encryptedSecret));
            auto jsonStr      = fmt::format("{{\"shared_secret\":\"{}\", \"client_id\":\"{}\"}}", sharedSecret, response.qoApiUID);
            // Print the secret and uuid
            std::cout << jsonStr << std::endl;
            break;
        }
        catch (const Quantinuum::QuantumOrigin::Common::ApiError &e)
        {
            connectionAttempts--;
            if (connectionAttempts == 0)
            {
                throw;
            }
        }
    }
}

// Create an ECC-CMS-SharedInfo structure as described in RFC 8418 section #2.
//
// ECC-CMS-SharedInfo ::= SEQUENCE {
//     keyInfo         AlgorithmIdentifier,
//     entityUInfo [0] EXPLICIT OCTET STRING OPTIONAL,
//     suppPubInfo [2] EXPLICIT OCTET STRING  }
std::vector<uint8_t> createEccCmsSharedInfo(const std::optional<std::vector<uint8_t>> &entityUinfo)
{
    // Hard-code the SharedInfo for hkdf-sha512 with ECDH curve SECP521R1 and 256-bit output size
    // TODO: This will need to be generated dynamically if we want to support other curves
    return {0x30, 0x14, 0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x03, 0x15,
            0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23, 0xa2, 0x06, 0x04, 0x04, 0x00, 0x01, 0x00, 0x00};
}

std::vector<uint8_t> CliOnboard::DecryptECDH(const mbedtls_pk_context &serverKey, const std::vector<uint8_t> &encryptedSecret)
{
    // Initialise ECDH context
    auto ecdhCtx = std::unique_ptr<mbedtls_ecdh_context, FreeMbedtlsEcdhCtx>(new mbedtls_ecdh_context);
    mbedtls_ecdh_init(ecdhCtx.get());

    // Set up the keys for both sides in the context
    CheckMbedRV(mbedtls_ecdh_get_params(ecdhCtx.get(), mbedtls_pk_ec(_userKey), MBEDTLS_ECDH_OURS), "Failed to load user EC params");
    CheckMbedRV(mbedtls_ecdh_get_params(ecdhCtx.get(), mbedtls_pk_ec(serverKey), MBEDTLS_ECDH_THEIRS), "Failed to load server EC params");

    std::vector<uint8_t> sharedSecret(MAX_EC_SHARED_SECRET_SIZE);
    size_t outLen = 0;

    // Derive the shared secret
    CheckMbedRV(
        mbedtls_ecdh_calc_secret(ecdhCtx.get(), &outLen, sharedSecret.data(), sharedSecret.size(), mbedtls_ctr_drbg_random, &_drbgCtx),
        "Failed to calculate ECDH shared secret");

    if (outLen > MAX_EC_SHARED_SECRET_SIZE)
    {
        throw std::runtime_error("Unexpected shared secret size");
    }

    sharedSecret.resize(outLen);

    if (std::all_of(sharedSecret.begin(), sharedSecret.end(), [](const auto &byte) { return byte == 0; }))
    {
        throw std::runtime_error("Derived all-zero shared secret");
    }

    // If salt (User Keying Material - UKM) is not provided, set to a string of HashLen zeros
    // TODO: Support a user-provided UKM
    std::vector<uint8_t> allZeros(64, 0);

    // First perform randomness extraction using the UKM/zeroes as the salt to produce a pseudorandom
    // key (PRK)
    // The salt is used as the key in the HMAC operation, and the shared secret used as the data,
    // this is intentional as described in RFC 5869 Section 2.1/2.2
    std::vector<uint8_t> prk(64);
    CheckMbedRV(
        mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA512), allZeros.data(), allZeros.size(), sharedSecret.data(), sharedSecret.size(), prk.data()),
        "Failed to perform HMAC");

    auto eccCmsSharedInfo = createEccCmsSharedInfo(std::nullopt);
    eccCmsSharedInfo.push_back((uint8_t)1); // Fixed counter for first block

    // Perform single-block HMAC to produce KEK (key encryption key)
    std::vector<uint8_t> kek(64);
    CheckMbedRV(
        mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA512), prk.data(), prk.size(), eccCmsSharedInfo.data(), eccCmsSharedInfo.size(), kek.data()),
        "Failed to perform HMAC");

    // Truncate to 32-bytes to be used for AES-256
    kek.resize(32);

    // For GCM we'll use a 96-bit IV
    // This consists of a 32-bit 'fixed field', for which we can just use all-zeros, since these keys will
    // only ever be used once, plus a 64-bit 'invocation field' containing an incrementing counter, which,
    // since we're only using this key once, will also always be 0.
    std::vector<uint8_t> iv = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    auto cipherCtx = std::unique_ptr<mbedtls_cipher_context_t, FreeMbedtlsCipherCtx>(new mbedtls_cipher_context_t);
    mbedtls_cipher_init(cipherCtx.get());

    CheckMbedRV(mbedtls_cipher_setup(cipherCtx.get(), mbedtls_cipher_info_from_values(MBEDTLS_CIPHER_ID_AES, 256, MBEDTLS_MODE_GCM)), "Failed to set up cipher context");
    CheckMbedRV(mbedtls_cipher_setkey(cipherCtx.get(), kek.data(), 256, MBEDTLS_DECRYPT), "Failed to set cipher key");
    CheckMbedRV(mbedtls_cipher_set_iv(cipherCtx.get(), iv.data(), iv.size()), "Failed to set cipher IV");

    // Decrypt the secret
    std::vector<uint8_t> decrypted(32);
    outLen = 32;
    CheckMbedRV(
        mbedtls_cipher_auth_decrypt_ext(
            cipherCtx.get(), iv.data(), iv.size(), nullptr, 0, encryptedSecret.data(), encryptedSecret.size(), decrypted.data(), decrypted.size(), &outLen, 16),
        "Failed to GCM decrypt");

    if (outLen != 32)
    {
        throw std::runtime_error("Unexpected decrypted output length");
    }

    return decrypted;
}

void CliOnboard::GenerateUserKey()
{
    CheckMbedRV(mbedtls_pk_setup(&_userKey, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)), "Failed to setup public key");
    CheckMbedRV(
        mbedtls_ecp_gen_key(mbedtls_ecp_group_id::MBEDTLS_ECP_DP_SECP521R1, mbedtls_pk_ec(_userKey), mbedtls_ctr_drbg_random, &_drbgCtx),
        "Failed to generate secp521R1 keypair");
}

size_t CliOnboard::CheckMbedRV(int rv, const std::string &failMsg)
{
    if (rv < 0)
    {
        const int buf_len = 200;
        char error_buf[buf_len];
        mbedtls_strerror(rv, error_buf, buf_len);
        auto msg = fmt::format("Error: {}, error_code = {} mbedtls_msg: {}", failMsg, rv, error_buf);
        spdlog::error(msg);
        throw std::runtime_error(msg);
    }
    return (size_t)rv;
}
