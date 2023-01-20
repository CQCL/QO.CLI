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
// IronBridge GCM Decryption
// Copyright 2020 Cambridge Quantum Computing Ltd. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution or at
// https://www.openssl.org/source/license.html
//
///////////////////////////////////////////////////////////////////////////////

#ifndef _INCLUDE_IBRAND_CRYPTO_GCM_H_
#define _INCLUDE_IBRAND_CRYPTO_GCM_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BITS_PER_BYTE (8)
#define PAYLOAD_TAG_LEN (16)
#define PAYLOAD_DATA_MINIMUM_LEN (16) // AES128 is currently the smallest key request that we support
#define SEED_LEN (36)
#define CIPHERKEY_LEN (32)
#define IV_LEN (12)
#define GCM_COUNTER_STARTING_VALUE_DEFAULT (0)  // Quantum origin always uses a starting counter value of zero



#ifndef tERRORCODE
#define tERRORCODE uint32_t
#endif
#ifndef ERC_OK
#define ERC_OK 0
#endif
#ifndef ERC_UNSPECIFIED_ERROR
#define ERC_UNSPECIFIED_ERROR 19999
#endif
#define ERC_IBGCM_FLOOR                                  11700

#define ERC_IBGCM_PARAMERR_KEY_NOT_SPECIFIED             11710
#define ERC_IBGCM_PARAMERR_DATAIN_NOT_SPECIFIED          11720
#define ERC_IBGCM_PARAMERR_SEED_NOT_SPECIFIED            11730
#define ERC_IBGCM_PARAMERR_NONCE_NOT_SPECIFIED           11740
#define ERC_IBGCM_PARAMERR_DATAOUT_NOT_SPECIFIED         11750
#define ERC_IBGCM_PARAMERR_DATAOUTLEN_NOT_VALID          11760
#define ERC_IBGCM_PARAMERR_KEYLEN_NOT_VALID              11770
#define ERC_IBGCM_PARAMERR_SEEDLEN_NOT_VALID             11780
#define ERC_IBGCM_PARAMERR_INPUTDATALEN_NOT_VALID        11790

#define ERC_IBGCM_KDERR_SIZE_OF_DERIVEDKEY_INVALID       11800
#define ERC_IBGCM_KDERR_NOMEM_FOR_DERIVEDKEY             11810
#define ERC_IBGCM_KDERR_HMAC_FOR_DERIVEDKEY_FAILED       11820

#define ERC_IBGCM_DECERR_NOMEM_FOR_DERIVEDKEY            11830
#define ERC_IBGCM_DECERR_OUTPUT_BUFFER_TOO_SMALL         11840
#define ERC_IBGCM_DECERR_SEED_IS_TOO_SHORT               11850
#define ERC_IBGCM_DECERR_UNSUPPORTED_KEYLEN              11860
#define ERC_IBGCM_DECERR_FAILED_TO_SET_GCM_KEY           11870
#define ERC_IBGCM_DECERR_AUTHENTICATED_DECRYPTION_FAILED 11880
#define ERC_IBGCM_DECERR_GCM_BAD_INPUT_PARAMETERS        11890
#define ERC_IBGCM_DECERR_GCM_UNSPECIFIED_ERROR           11900
#define ERC_IBGCM_DECERR_NOMEM_FOR_PLAINTEXT             11910
#define ERC_IBGCM_DECERR_UNEXPECTED_OUTPUT_LEN           11920

extern const char *qo_decrypt_about(void);
extern const char *qo_decrypt_version(void);
extern const char *qo_decrypt_error_description(tERRORCODE rc);

extern tERRORCODE qo_decrypt_aes_gcm(const uint8_t *pSharedSecret,        size_t cbSharedSecret,     // Shared Secret, from OnBoarding(32 bytes) (A)                                                                       (32 is the CIPHERKEY_LEN)
                                     const uint8_t *pCipherTextAndTag,    size_t cbCipherTextAndTag, // Encrypted New Key, from the response (>= 16 bytes) (D)                                                             (16 is the PAYLOAD_TAG_LEN)
                                     const uint8_t *pSeed,                size_t cbSeed,             // Seed, from the response (always 36 bytes) (E)                                                                      (36 is the SEED_LEN)
                                     uint64_t       counterStartingValue,                            // integer, from the response (C)                                                                                     (GCM counter)
                                     const uint8_t *pNonce,               size_t cbNonce,            // Unique Nonce (B)                                                                                                   (used as the GCM authenticated_data)
                                     uint8_t       *pPlainTextOut,        size_t cbPlainTextOut,     // Ptr to pre-existing output buffer and associated size. The size of the buffer must be >= (cbCipherText - 16) (F)   (16 is the PAYLOAD_TAG_LEN)
                                     size_t        *pPlainTextSignificantLength);                    // The number of bytes actually written to pPlainTextOut. Will always be <= cbPlainTextOut.

#ifdef __cplusplus
}
#endif

#endif // _INCLUDE_IBRAND_CRYPTO_GCM_H_
