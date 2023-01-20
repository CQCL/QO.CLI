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

///////////////////////////////////////////////////////////////////////////////
// IronBridge Crypto Library
///////////////////////////////////////////////////////////////////////////////

// Implementation:
// Both this C library and the Rust library use the GCM that is included in the mbedcrypto library.
// The way in which this GCM function is called is proprietary/specific to IronBridge, and includes specific handling of:
//   * The derived key (from the sharedSecret and the Seed),
//   * The IV (part of the seed and the counter),
//   * The nonce
//   * The tag (the last 16 bytes of the encrypted new key).
//   * The balance of the encrypted new key
// These are all constructed and then passed into GCM in the mbedcrypto library.
// ClientCrypt on Server-Side does the equivalent at encipher time.

//#pragma comment(lib, "qo_crypto.lib")


#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <assert.h>

#include <mbedtls/cipher.h> // For mbedtls_cipher_init() etc.
#include <mbedtls/hkdf.h>
#include <mbedtls/gcm.h>
#include <mbedtls/error.h>
#include <mbedtls/md.h>
#define MBEDTLS_ERR_SUCCESS (0)

#include <qo_utils/qo_string.h>
#include <qo_utils/qo_logging.h>

#include <qo_decrypt/qo_crypto.h>

//#include <qo_decrypt/qo_decrypt_project_config.h>
// Example contents of qo_decrypt_project_config.h
//     #define QO_DECRYPT_PROJECT_NAME       "qo_decrypt"
//     #define QO_DECRYPT_PROJECT_VER        "1.30.0"
//     #define QO_DECRYPT_PROJECT_VER_MAJOR  "1"
//     #define QO_DECRYPT_PROJECT_VER_MINOR  "30"
//     #define QO_DECRYPT_PROJECT_VER_PATCH  "0"

#define QO_LIB_LIBRARYNAME        "Quantum Origin Decrypt Library"
#define QO_LIB_COPYRIGHT          "Copyright (c) 2021-2022 Cambridge Quantum. All rights reserved."
#define QO_LIB_LIBRARYNAME_LONG   QO_DECRYPT_PROJECT_NAME ": " QO_LIB_LIBRARYNAME " v" QO_DECRYPT_PROJECT_VER "\n" QO_LIB_COPYRIGHT "\n"
#define QO_LIB_ABOUT              QO_LIB_LIBRARYNAME_LONG

// IEEE big-endian format is used for the network format.
uint32_t htonl (uint32_t x)
{
#if BYTE_ORDER == BIG_ENDIAN
	return x;
#elif BYTE_ORDER == LITTLE_ENDIAN
	return __bswap_32 (x);
#endif
}

#define HTONLL(x) ((1==htonl(1)) ? (x) : (((uint64_t)htonl((x) & 0xFFFFFFFFUL)) << 32) | htonl((uint32_t)((x) >> 32)))
#define NTOHLL(x) ((1==ntohl(1)) ? (x) : (((uint64_t)ntohl((x) & 0xFFFFFFFFUL)) << 32) | ntohl((uint32_t)((x) >> 32)))
//#define HTONLL(x) htonll(x)
//#define NTOHLL(x) ntohll(x)

//#define LOCAL_DEBUG_TRACING

const char *qo_decrypt_about(void)
{
    return QO_LIB_ABOUT;
}

const char *qo_decrypt_version(void)
{
    return QO_DECRYPT_PROJECT_VER;
}


// HKDF key derivation (see RFC 5869)
static tERRORCODE derive_encryption_key(const uint8_t *pSeed,           size_t cbSeed,         // 36 (SEED_LEN)
                                        const uint8_t *pSharedSecret,   size_t cbSharedSecret, // 32 (CIPHERKEY_LEN)
                                        uint8_t *pDerivedKey32, size_t cbDerivedKey32)         // 32 (CIPHERKEY_LEN)
{
    // Same logic as IronBridge.Software.ARQ-Shared-rs/arq_crypto/src/hkdf.rs
    // The key we have is already secure and cryptographically random, so we shouldn't need to
    // perform randomness extraction, and we can skip straight to the expansion step.
    // We perform expansion by calculating the HMAC with our key on our info.
    // This can be done in multiple blocks with a counter and feedback to produce multiple blocks
    //  of output, but since we only need 256-bit of output we can simplify this by just doing a
    // single block with the counter fixed at 1

    ////////////////////////////////////////////////////////////////////////////////////////////////
    //  Extracts from reference_code\ARMmbed\mbedtls\library\md_wrap.h
    //
    // // Message digest information.
    // const mbedtls_md_info_t mbedtls_sha256_info = { "SHA256",            // const char *      name;       - Name of the message digest
    //                                                 MBEDTLS_MD_SHA256,   // mbedtls_md_type_t type;       - Digest identifier, defined in from reference_code\ARMmbed\mbedtls\library\md_wrap.h
    //                                                 32,                  // unsigned char     size;       - Output length of the digest function in bytes
    //                                                 64 };                // unsigned char     block_size; - Block length of the digest function in bytes
    //
    // // HMAC
    // int mbedtls_md_hmac( const mbedtls_md_info_t *md_info,
    //                      const unsigned char *key, size_t keylen,
    //                      const unsigned char *input, size_t ilen,
    //                      unsigned char *output );
    ////////////////////////////////////////////////////////////////////////////////////////////////

    if (cbDerivedKey32 != CIPHERKEY_LEN) // Always 32 bytes for MBEDTLS_MD_SHA256
    {
        app_tracef("ERROR: derive_encryption_key result buffer too small");
        return ERC_IBGCM_KDERR_SIZE_OF_DERIVEDKEY_INVALID;
    }

    size_t seedBytesToUse = cbSeed - 4;
    size_t cbInputData = seedBytesToUse + 1;
    uint8_t *pInputData = malloc(cbInputData);
    if (pInputData == NULL)
    {
        app_tracef("ERROR: Failed to allocate memory for key derivation");
        return ERC_IBGCM_KDERR_NOMEM_FOR_DERIVEDKEY;
    }
    memcpy(pInputData, pSeed, seedBytesToUse);  // Our info will consist of just the random seed
    pInputData[seedBytesToUse] = 1;             // Fixed counter for first block

    const mbedtls_md_info_t *pMdInfo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256); // mbedtls_sha256_info

#ifdef LOCAL_DEBUG_TRACING
    app_trace_hexall("DEBUG: RFC5869 SharedSecret   =", pSharedSecret, cbSharedSecret);
    app_trace_hexall("DEBUG: RFC5869 InputData      =", pInputData, cbInputData);
#endif // LOCAL_DEBUG_TRACING

    // Perform single-block HMAC to produce OKM (output keying material)
    int rc = mbedtls_md_hmac(pMdInfo,
                             pSharedSecret, cbSharedSecret,
                             pInputData, cbInputData,
                             pDerivedKey32);
    if (rc != 0)
    {
        app_tracef("ERROR: mbedtls_md_hmac() failed with rc=%d", rc);
        qo_CleanseAndFree(&pInputData, cbInputData);
        return ERC_IBGCM_KDERR_HMAC_FOR_DERIVEDKEY_FAILED;
    }
#ifdef LOCAL_DEBUG_TRACING
    app_trace_hexall("DEBUG: RFC5869 Result         =", pDerivedKey32, cbDerivedKey32);
#endif // LOCAL_DEBUG_TRACING

    qo_CleanseAndFree(&pInputData, cbInputData);

    return 0;
}


static tERRORCODE decrypt_aes_gcm(const uint8_t *pSharedSecret,     size_t cbSharedSecret,     // rootKey (always AES256 i.e. 32 bytes (CIPHERKEY_LEN))
                                  const uint8_t *pSeed,             size_t cbSeed,             // seed (always 36 bytes (SEED_LEN))
                                  uint64_t       counterStartingValue,                         // counter
                                  const uint8_t *pCipherTextAndTag, size_t cbCipherTextAndTag, // Tag length is always 16 (PAYLOAD_TAG_LEN), so this must be >= 16 bytes (PAYLOAD_TAG_LEN)
                                  const uint8_t *pNonce,            size_t cbNonce,            // authenticated_data
                                  uint8_t       *pPlainTextOut,     size_t cbPlainTextOut,     // Ptr to pre-existing output buffer (in which to write the plainTextResult) and associated size. The size of the buffer must be >= (cbCipherText - PAYLOAD_TAG_LEN(16))
                                  size_t        *pPlainTextSignificantLength)                     // The number of bytes actually written to pPlainTextOut. Will always be <= cbPlainTextOut.
{
    // GCM:   Galois/Counter Mode (https://en.wikipedia.org/wiki/Galois/Counter_Mode)
    //        GCM is an authenticated encryption algorithm designed to provide both data authenticity (integrity) and confidentiality.
    //        GCM is defined for block ciphers with a block size of 128 bits.
    // AEAD: Authenticated Encryption with Associated Data

    // AES-GCM is an authenticated encryption mode that uses the AES block cipher in counter mode
    // with a polynomial MAC based on Galois field multiplication.
    //
    // AES-GCM is an authenticated encryption mode that also supports additional authenticated data.
    // Cryptographers call these modes AEAD. The output of an AEAD function is both the ciphertext
    // and an authentication tag, which is necessary (along with the key and nonce, and optional
    // additional data) to decrypt the plaintext.

    // AES only includes three flavors of Rijndael: AES-128, AES-192, and AES-256.
    // The difference between these flavors is the size of the key and the number of rounds used,
    // but–and this is often overlooked–not the block size.
    // As a block cipher, AES always operates on 128-bit (16 byte) blocks of plaintext, regardless of the key size.

    //decrypted = match do_decrypt(key_slice, cipher_slice, seed_slice, counter as u64, nonce_slice);
    // i.e. decrypt(root_key, seed, counter, ciphertext, nonce_slice) // authenticated_data is the nonce_slice

    tERRORCODE rc = 0;

#ifdef LOCAL_DEBUG_TRACING
    app_tracef      ("DEBUG: INPUT PARAMS...");
    app_trace_hexall("DEBUG:     pSharedSecret      =", pSharedSecret, cbSharedSecret);
    app_trace_hexall("DEBUG:     pSeed              =", pSeed, cbSeed);
    app_tracef      ("DEBUG:     counter            = %lu", counterStartingValue);
    app_trace_hexall("DEBUG:     pCipherTextAndTag  =", pCipherTextAndTag, cbCipherTextAndTag);
    app_trace_hexall("DEBUG:     pNonce             =", pNonce, cbNonce);
#endif // LOCAL_DEBUG_TRACING


    if (pPlainTextSignificantLength)
        *pPlainTextSignificantLength = 0;

    /////////////////////////////////////////////////////////////////////////////////////////////
    // PART ONE
    /////////////////////////////////////////////////////////////////////////////////////////////
    size_t cbDerivedKey = CIPHERKEY_LEN;
    uint8_t *pDerivedKey = malloc(cbDerivedKey);
    //uint8_t expectedKey[] = {0x75,0xE3,0x74,0xF3,0x21,0xDC,0x1B,0x03,0x50,0xE9,0x97,0x39,0xD1,0x37,0xE6,0x52,0x82,0x1F,0x0B,0x55,0xCC,0xCC,0x34,0xAA,0xCC,0x12,0x27,0x4C,0x5B,0x7F,0x02,0xC5};
    //UNUSED_VAR(expectedKey);

    if (pDerivedKey == NULL)
    {
        app_tracef("ERROR: Failed to allocate memory for derivedKey");
        return ERC_IBGCM_DECERR_NOMEM_FOR_DERIVEDKEY;
    }
    // Derive encryption key from the seed
    rc = derive_encryption_key(pSeed, cbSeed, pSharedSecret, cbSharedSecret, pDerivedKey, cbDerivedKey);
    if (rc != 0)
    {
        app_tracef("ERROR: derive_encryption_key() failed with rc=%d", rc);
        qo_CleanseAndFree(&pDerivedKey, cbDerivedKey);
        return rc;
    }
#ifdef LOCAL_DEBUG_TRACING
    app_trace_hexall("DEBUG: pDerivedKey            =" , pDerivedKey, cbDerivedKey );
#endif // LOCAL_DEBUG_TRACING

    /////////////////////////////////////////////////////////////////////////////////////////////
    // PART TWO
    /////////////////////////////////////////////////////////////////////////////////////////////
    if (cbPlainTextOut == 0) // was < 32 - I don't think we can presume the size of the output at all
    {
        app_tracef("ERROR: Output buffer too small (%u)", cbPlainTextOut);
        qo_CleanseAndFree(&pDerivedKey, cbDerivedKey);
        return ERC_IBGCM_DECERR_OUTPUT_BUFFER_TOO_SMALL;
    }

    // Construct the IV that was used at encryption time
    if (cbSeed <= 4)
    {
        app_tracef("ERROR: Seed is too short. Must be more than 4 bytes in length");
        qo_CleanseAndFree(&pDerivedKey, cbDerivedKey);
        return ERC_IBGCM_DECERR_SEED_IS_TOO_SHORT;
    }
    uint8_t iv[IV_LEN];
    memcpy(iv, pSeed+cbSeed-4, 4);  // Copy the last 4 bytes of the seed into the first 4 bytes of the iv.
    uint64_t counterLE = HTONLL(counterStartingValue);
    uint8_t *pSrc = (uint8_t *)(&counterLE);
    uint8_t *pDst = iv + 4;
    memcpy(pDst, pSrc, sizeof(counterStartingValue)); // Copy all 8 bytes of the counter (represented in LittleEndian format) to the next 8 bytes of the iv.

#ifdef LOCAL_DEBUG_TRACING
    app_tracef      ("DEBUG: counter                = %lu", counterStartingValue);
    app_tracef      ("DEBUG: counter (LittleEndian) = %lu", counterLE);
    app_trace_hexall("DEBUG: counter                =", (uint8_t*)&counterStartingValue, sizeof(counterStartingValue));
    app_trace_hexall("DEBUG: counter (LittleEndian) =", (uint8_t*)&counterLE, sizeof(counterLE));
    app_trace_hexall("DEBUG: iv                     =", iv, sizeof(iv));
#endif // LOCAL_DEBUG_TRACING

    // Perform the decryption
    mbedtls_gcm_context ctx;
    size_t cbitsDerivedKey = cbDerivedKey * BITS_PER_BYTE;
    const uint8_t *pTag = pCipherTextAndTag + (cbCipherTextAndTag - PAYLOAD_TAG_LEN);
    size_t cbTag = PAYLOAD_TAG_LEN;

    mbedtls_gcm_init(&ctx);
    if (cbitsDerivedKey != 256)
    {
        app_tracef("ERROR: Unsupported key length: %u bytes (%u bits)", cbDerivedKey, cbitsDerivedKey);
        qo_CleanseAndFree(&pDerivedKey, cbDerivedKey);
        return ERC_IBGCM_DECERR_UNSUPPORTED_KEYLEN;
    }

    rc = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, pDerivedKey, cbitsDerivedKey);
    if (rc != 0)
    {
        app_tracef("ERROR: mbedtls_gcm_setkey() failed with rc=%d", rc);
        qo_CleanseAndFree(&pDerivedKey, cbDerivedKey);
        return ERC_IBGCM_DECERR_FAILED_TO_SET_GCM_KEY;
    }

#ifdef LOCAL_DEBUG_TRACING
    app_tracef      ("DEBUG: DECRYPTING...");
    app_tracef      ("DEBUG:     cbCipherTextAndTag = %u", cbCipherTextAndTag);
    app_trace_hexall("DEBUG:     iv                 =", iv, sizeof(iv));
    app_trace_hexall("DEBUG:     pNonce             =", pNonce, cbNonce);
    app_trace_hexall("DEBUG:     pTag               =", pTag, cbTag);
    app_trace_hexall("DEBUG:     pCipherTextAndTag  =", pCipherTextAndTag, cbCipherTextAndTag);
#endif // LOCAL_DEBUG_TRACING

    size_t cbCipherText = cbCipherTextAndTag-PAYLOAD_TAG_LEN;
    rc = mbedtls_gcm_auth_decrypt(&ctx,
                                  cbCipherText,      // size_t length
                                  iv, sizeof(iv),    // const unsigned char *iv, size_t iv_len
                                  pNonce, cbNonce,   // const unsigned char *add, size_t add_len
                                  pTag, cbTag,       // const unsigned char *tag, size_t PAYLOAD_TAG_LEN
                                  pCipherTextAndTag, // const unsigned char *input
                                  pPlainTextOut);    // unsigned char *output - a buffer of at least <length> bytes i.e. cblengthOfActualCipherText
    if (rc != 0)
    {
         // returns 0 if the encryption or decryption was performed successfully. Note that in MBEDTLS_GCM_DECRYPT mode, this does not indicate that the data is authentic.
         // returns MBEDTLS_ERR_GCM_BAD_INPUT if the lengths or pointers are not valid or a cipher-specific error code if the encryption or decryption failed.
        switch (rc)
        {
            case MBEDTLS_ERR_GCM_AUTH_FAILED: // -0x0012  (-18) Authenticated decryption failed.
#ifdef LOCAL_DEBUG_TRACING
                app_tracef("ERROR (mbedtls): mbedtls_gcm_auth_decrypt() - Authenticated decryption failed (rc=%d=MBEDTLS_ERR_GCM_AUTH_FAILED).", rc);
#endif // LOCAL_DEBUG_TRACING
                rc = ERC_IBGCM_DECERR_AUTHENTICATED_DECRYPTION_FAILED;
                break;
            case MBEDTLS_ERR_GCM_BAD_INPUT  : // -0x0014  (-20) Bad input parameters to function.
#ifdef LOCAL_DEBUG_TRACING
                app_tracef("ERROR (mbedtls): mbedtls_gcm_auth_decrypt() - Bad input parameters to function (rc=%d=MBEDTLS_ERR_GCM_BAD_INPUT).", rc);
#endif // LOCAL_DEBUG_TRACING
                rc = ERC_IBGCM_DECERR_GCM_BAD_INPUT_PARAMETERS;
                break;
            default:
#ifdef LOCAL_DEBUG_TRACING
                app_tracef("ERROR (mbedtls): mbedtls_gcm_auth_decrypt() - Unspecified error (rc=%d)", rc);
#endif // LOCAL_DEBUG_TRACING
                rc = ERC_IBGCM_DECERR_GCM_UNSPECIFIED_ERROR;
                break;
        }
    }
    else
    {
      if (pPlainTextSignificantLength) {
        *pPlainTextSignificantLength = cbCipherText;
      }
    }

    mbedtls_gcm_free(&ctx);
    qo_CleanseAndFree(&pDerivedKey, cbDerivedKey);

    return rc;
}


tERRORCODE qo_decrypt_aes_gcm(const uint8_t *pSharedSecret,        size_t cbSharedSecret,     // Shared Secret, from OnBoarding(32 bytes) (A)                                                                       (32 is the CIPHERKEY_LEN)
                              const uint8_t *pCipherTextAndTag,    size_t cbCipherTextAndTag, // Encrypted New Key, from the response (>= 16 bytes) (D)                                                             (16 is the PAYLOAD_TAG_LEN)
                              const uint8_t *pSeed,                size_t cbSeed,             // Seed, from the response (always 36 bytes) (E)                                                                      (36 is the SEED_LEN)
                              uint64_t       counterStartingValue,                            // integer, from the response (C)                                                                                     (GCM counter)
                              const uint8_t *pNonce,               size_t cbNonce,            // Unique Nonce (B)                                                                                                   (This is used as the GCM authenticated_data)
                              uint8_t       *pPlainTextOut,        size_t cbPlainTextOut,     // Ptr to pre-existing output buffer and associated size. The size of the buffer must be >= (cbCipherText - 16) (F)   (16 is the PAYLOAD_TAG_LEN)
                              size_t        *pPlainTextSignificantLength)                     // The number of bytes actually written to pPlainTextOut. Will always be <= cbPlainTextOut.
{
    UNUSED_PARAM(counterStartingValue);

    size_t         sizeOfCallersOutputBuffer = 0;
    tERRORCODE rc = 0;
    tERRORCODE firstError = 0;

#ifdef LOCAL_DEBUG_TRACING
    app_tracef("INFO: ********************** qo_decrypt_aes_gcm ENTRY **********************");
#endif // LOCAL_DEBUG_TRACING

    // Validate Parameters
    if (!pSharedSecret)                                        { rc = ERC_IBGCM_PARAMERR_KEY_NOT_SPECIFIED;         app_tracef("ERROR: %s", qo_decrypt_error_description(rc)); if (firstError==0) firstError = rc; }
    if (!pCipherTextAndTag)                                    { rc = ERC_IBGCM_PARAMERR_DATAIN_NOT_SPECIFIED;      app_tracef("ERROR: %s", qo_decrypt_error_description(rc)); if (firstError==0) firstError = rc; }
    if (!pSeed)                                                { rc = ERC_IBGCM_PARAMERR_SEED_NOT_SPECIFIED;        app_tracef("ERROR: %s", qo_decrypt_error_description(rc)); if (firstError==0) firstError = rc; }
#if INTERNAL_BUILD
    if (!pNonce && cbNonce != 0)                               { rc = ERC_IBGCM_PARAMERR_NONCE_NOT_SPECIFIED;       app_tracef("ERROR: %s", qo_decrypt_error_description(rc)); if (firstError==0) firstError = rc; }
#else
    if (!pNonce || cbNonce == 0)                               { rc = ERC_IBGCM_PARAMERR_NONCE_NOT_SPECIFIED;       app_tracef("ERROR: %s", qo_decrypt_error_description(rc)); if (firstError==0) firstError = rc; }
#endif
    if (!pPlainTextOut)                                        { rc = ERC_IBGCM_PARAMERR_DATAOUT_NOT_SPECIFIED;     app_tracef("ERROR: %s", qo_decrypt_error_description(rc)); if (firstError==0) firstError = rc; }
    if (cbPlainTextOut < (cbCipherTextAndTag-PAYLOAD_TAG_LEN)) { rc = ERC_IBGCM_PARAMERR_DATAOUTLEN_NOT_VALID;      app_tracef("ERROR: %s", qo_decrypt_error_description(rc)); if (firstError==0) firstError = rc; }
    if (cbSharedSecret != CIPHERKEY_LEN)                       { rc = ERC_IBGCM_PARAMERR_KEYLEN_NOT_VALID;          app_tracef("ERROR: %s", qo_decrypt_error_description(rc)); if (firstError==0) firstError = rc; }
    if (cbSeed != SEED_LEN)                                    { rc = ERC_IBGCM_PARAMERR_SEEDLEN_NOT_VALID;         app_tracef("ERROR: %s", qo_decrypt_error_description(rc)); if (firstError==0) firstError = rc; }
    if (cbCipherTextAndTag < PAYLOAD_TAG_LEN)                  { rc = ERC_IBGCM_PARAMERR_INPUTDATALEN_NOT_VALID;    app_tracef("ERROR: %s", qo_decrypt_error_description(rc)); if (firstError==0) firstError = rc; }
    if (rc)
    {
        // One or more errors have already been reported
        return firstError;
    }
#ifdef LOCAL_DEBUG_TRACING
    app_tracef("INFO: Parameters OK");
#endif // LOCAL_DEBUG_TRACING

    sizeOfCallersOutputBuffer = cbPlainTextOut;
    memset(pPlainTextOut, 0xAA, cbPlainTextOut);

    rc = decrypt_aes_gcm(pSharedSecret, cbSharedSecret,
                         pSeed, cbSeed,
                         counterStartingValue,
                         pCipherTextAndTag, cbCipherTextAndTag,
                         pNonce, cbNonce,
                         pPlainTextOut, cbPlainTextOut,
                         pPlainTextSignificantLength);
    if (rc != 0)
    {
#ifdef LOCAL_DEBUG_TRACING
        app_tracef("ERROR: decrypt_aes_gcm failed with rc=%d", rc);
#endif // LOCAL_DEBUG_TRACING
        return rc;
    }

    if (*pPlainTextSignificantLength != cbCipherTextAndTag-PAYLOAD_TAG_LEN)
    {
        rc = ERC_IBGCM_DECERR_UNEXPECTED_OUTPUT_LEN;
        app_tracef("ERROR: Length of decrypted data (%u) is not as expected (%u) (rc=%d)", *pPlainTextSignificantLength, cbCipherTextAndTag-PAYLOAD_TAG_LEN, rc);
        return rc;
    }

    // Success
#ifdef LOCAL_DEBUG_TRACING
    app_tracef      ("DEBUG: DECRYPT SUCCESFULL...");
    app_trace_hexall("DEBUG:     pPlainTextOut      =" , pPlainTextOut, *pPlainTextSignificantLength);
#endif // LOCAL_DEBUG_TRACING

#ifdef LOCAL_DEBUG_TRACING
    app_tracef("INFO: ********************** qo_decrypt_aes_gcm EXIT ***********************");
#endif // LOCAL_DEBUG_TRACING
    return ERC_OK;
}

const char *qo_decrypt_error_description(tERRORCODE rc)
{
    const char *pErrorStr;

    switch (rc)
    {
        case ERC_OK                                          : pErrorStr = ""; break;
        case ERC_IBGCM_PARAMERR_KEY_NOT_SPECIFIED            : pErrorStr = "Parameter error - Key (SharedSecret) not specified or invalid"; break;
        case ERC_IBGCM_PARAMERR_DATAIN_NOT_SPECIFIED         : pErrorStr = "Parameter error - Input Data not specified or invalid"; break;
        case ERC_IBGCM_PARAMERR_SEED_NOT_SPECIFIED           : pErrorStr = "Parameter error - Seed not specified or invalid"; break;
        case ERC_IBGCM_PARAMERR_NONCE_NOT_SPECIFIED          : pErrorStr = "Parameter error - Nonce not specified or invalid"; break;
        case ERC_IBGCM_PARAMERR_DATAOUT_NOT_SPECIFIED        : pErrorStr = "Parameter error - Buffer for output data not specified or invalid"; break;
        case ERC_IBGCM_PARAMERR_DATAOUTLEN_NOT_VALID         : pErrorStr = "Parameter error - Output buffer length must be at least ciphertext length minus 16 bytes (i.e. PAYLOAD_TAG_LEN)"; break;
        case ERC_IBGCM_PARAMERR_KEYLEN_NOT_VALID             : pErrorStr = "Parameter error - SharedSecret length must be 32 bytes"; break;
        case ERC_IBGCM_PARAMERR_SEEDLEN_NOT_VALID            : pErrorStr = "Parameter error - Seed length must be 36 bytes"; break;
        case ERC_IBGCM_PARAMERR_INPUTDATALEN_NOT_VALID       : pErrorStr = "Parameter error - Ciphertext length must be at least 16 byte (i.e. PAYLOAD_TAG_LEN)"; break;

        case ERC_IBGCM_KDERR_SIZE_OF_DERIVEDKEY_INVALID      : pErrorStr = "Key derivation error - Size of derived key is invalid"; break;
        case ERC_IBGCM_KDERR_NOMEM_FOR_DERIVEDKEY            : pErrorStr = "Key derivation error - No memory for derived key working storage"; break;
        case ERC_IBGCM_KDERR_HMAC_FOR_DERIVEDKEY_FAILED      : pErrorStr = "Key derivation error - HMAC for derived key failed"; break;

        case ERC_IBGCM_DECERR_NOMEM_FOR_DERIVEDKEY           : pErrorStr = "Decryption error - No memory for derived key"; break;
        case ERC_IBGCM_DECERR_OUTPUT_BUFFER_TOO_SMALL        : pErrorStr = "Decryption error - Output buffer too small"; break;
        case ERC_IBGCM_DECERR_SEED_IS_TOO_SHORT              : pErrorStr = "Decryption error - Seed is too short. Must be more than 4 bytes in length"; break;
        case ERC_IBGCM_DECERR_UNSUPPORTED_KEYLEN             : pErrorStr = "Decryption error - Unsupported key len"; break;
        case ERC_IBGCM_DECERR_FAILED_TO_SET_GCM_KEY          : pErrorStr = "Decryption error - Failed to set gcm key"; break;
        case ERC_IBGCM_DECERR_AUTHENTICATED_DECRYPTION_FAILED: pErrorStr = "Decryption error - Authenticated decryption failed"; break;
        case ERC_IBGCM_DECERR_GCM_BAD_INPUT_PARAMETERS       : pErrorStr = "Decryption error - GCM bad input parameters"; break;
        case ERC_IBGCM_DECERR_GCM_UNSPECIFIED_ERROR          : pErrorStr = "Decryption error - GCM unspecified error"; break;
        case ERC_IBGCM_DECERR_NOMEM_FOR_PLAINTEXT            : pErrorStr = "Decryption error - No memory for decrypted data"; break;
        case ERC_IBGCM_DECERR_UNEXPECTED_OUTPUT_LEN          : pErrorStr = "Decryption error - Length of decrypted data is not as expected"; break;

        default:
        case ERC_IBGCM_FLOOR                                 :
        case ERC_UNSPECIFIED_ERROR                           : pErrorStr = "Unspecified error"; break;
    }
    return pErrorStr;
}
