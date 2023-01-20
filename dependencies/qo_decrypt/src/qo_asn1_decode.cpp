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

#include <stdint.h>
#include <cstring>
#include <cstdlib>

#include <mbedtls/asn1.h>
#include <mbedtls/error.h>

#include <qo_decrypt/qo_crypto.h>


int CheckAsn1Error(int errorCode)
{
    if (errorCode != ASN1_DECODE_SUCCESS)
    {
        char buffer[200];
        mbedtls_strerror(errorCode, buffer, 200);
        fprintf(stderr, "ERROR: ASN.1 Decode: Last error was: %d - %s\n", errorCode, buffer);
    }
    return errorCode;
}


int qo_asn1_decode_ecx(unsigned char *pSrc, size_t srcLen, uint8_t **pDestPubKey, size_t *pDestPubKeyLen, uint8_t **pDestPrivKey, size_t *pDestPrivKeyLen)
{
    size_t seqLen;
    const uint8_t *pEnd = (pSrc + srcLen);

    // The "pSrc" points to head of SEQUENCE object, tag (0x10)
    // Each call to mbedtls_asn1_get_tag() will set the "pSrc" to the content that follows the tag+length info.

    // The following call will set the "pSrc" to the content after the SEQUENCE object,i.e, header of INTEGER
    int rv = CheckAsn1Error(mbedtls_asn1_get_tag(&pSrc,
                                                 pEnd,
                                                 &seqLen,
                                                 MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ));
    if (rv != ASN1_DECODE_SUCCESS)
    {
        return rv;
    }

    // The following call will set the "pSrc" to the content after the INTEGER object
    size_t intLen;
    rv = CheckAsn1Error(mbedtls_asn1_get_tag(&pSrc,
                                             pEnd,
                                             &intLen,
                                             MBEDTLS_ASN1_INTEGER));
    if (rv != ASN1_DECODE_SUCCESS)
    {
        return rv;
    }

    pSrc += intLen; // Advancing to private key, by jumping over INTEGER object

    size_t privLen;
    rv = CheckAsn1Error(mbedtls_asn1_get_tag(&pSrc,
                                             pEnd,
                                             &privLen,
                                             MBEDTLS_ASN1_OCTET_STRING));
    if (rv != ASN1_DECODE_SUCCESS)
    {
        return rv;
    }
    *pDestPrivKeyLen = privLen;
    *pDestPrivKey = (uint8_t*) malloc(privLen);
    if (*pDestPrivKey == nullptr)
    {
        fprintf(stderr,"ERROR: Failed to allocate %zu bytes of memory for private key\n", privLen);
        return ASN1_DECODE_ALLOC_FAILURE;
    }
    memcpy(*pDestPrivKey, pSrc, privLen);

    pSrc += privLen; // Advancing to oid part

    size_t oidLen;
    rv = CheckAsn1Error(mbedtls_asn1_get_tag(&pSrc,
                                             pEnd,
                                             &oidLen,
                                             MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC));
    if (rv != ASN1_DECODE_SUCCESS)
    {
        return rv;
    }

    pSrc += oidLen; // Advancing to public key part

    size_t pubLen;
    rv = CheckAsn1Error(mbedtls_asn1_get_tag(&pSrc,
                                             pEnd,
                                             &pubLen,
                                             MBEDTLS_ASN1_BOOLEAN | MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC ));
    if (rv != ASN1_DECODE_SUCCESS)
    {
        return rv;
    }
    *pDestPubKeyLen = pubLen;
    *pDestPubKey = (uint8_t*) malloc(pubLen);
    if (*pDestPubKey == nullptr)
    {
        fprintf(stderr,"ERROR: Failed to allocate %zu bytes of memory for public key\n", privLen);
        return ASN1_DECODE_ALLOC_FAILURE;
    }
    memcpy(*pDestPubKey, pSrc, pubLen);

    return ASN1_DECODE_SUCCESS;
}


int qo_asn1_decode_pqc(unsigned char *pSrc, size_t srcLen, uint8_t **pDestPubKey, size_t *pDestPubKeyLen, uint8_t **pDestPrivKey, size_t *pDestPrivKeyLen)
{
    size_t seqLen, pubLen, privLen;
    const uint8_t *pEnd = (pSrc + srcLen);

    // The "pSrc" points to head of SEQUENCE object, tag (0x10) + length (tag + 4 bytes + pubkey + tag + 4 bytes + privkey)
    // Each call to mbedtls_asn1_get_tag() will set the "pSrc" to the content that follows the tag+length info.

    // The following call will set the "pSrc" to the content after the SEQUENCE object,i.e, header of OCTET_STRING
    int rv = CheckAsn1Error(mbedtls_asn1_get_tag(&pSrc,
                                                 pEnd,
                                                 &seqLen,
                                                 MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ));
    if (rv != ASN1_DECODE_SUCCESS)
    {
        return rv;
    }

    // The following call will set the "pSrc" to the content after the OCTET_STRING object, i.e, the public key
    rv = CheckAsn1Error(mbedtls_asn1_get_tag(&pSrc,
                                             pEnd,
                                             &pubLen,
                                             MBEDTLS_ASN1_OCTET_STRING));
    if (rv != ASN1_DECODE_SUCCESS)
    {
        return rv;
    }
    *pDestPubKeyLen = pubLen;
    *pDestPubKey = (uint8_t*) malloc(pubLen);
    if (*pDestPubKey == nullptr)
    {
        fprintf(stderr,"ERROR: Failed to allocate %zu bytes of memory for public key\n", pubLen);
        return ASN1_DECODE_ALLOC_FAILURE;
    }
    memcpy(*pDestPubKey, pSrc, pubLen);

    pSrc += pubLen;  // Advance to private key.
    rv = CheckAsn1Error(mbedtls_asn1_get_tag(&pSrc,
                                             pEnd,
                                             &privLen,
                                             MBEDTLS_ASN1_OCTET_STRING));
    if (rv != ASN1_DECODE_SUCCESS)
    {
        return rv;
    }
    *pDestPrivKeyLen = privLen;
    *pDestPrivKey = (uint8_t *)malloc(privLen);
    if (*pDestPrivKey == nullptr)
    {
        fprintf(stderr,"ERROR: Failed to allocate %zu bytes of memory for private key\n", privLen);
        return ASN1_DECODE_ALLOC_FAILURE;
    }
    memcpy(*pDestPrivKey, pSrc, privLen);

    return ASN1_DECODE_SUCCESS;
}
