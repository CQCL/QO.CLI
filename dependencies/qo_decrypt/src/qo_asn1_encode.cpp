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
#include <mbedtls/asn1write.h>
#include <mbedtls/error.h>
#include <cstdlib>
#include <vector>
#include "qo_decrypt/qo_asn1_encode.h"


int CheckAsn1EncodeError(int errorCode)
{
    if (errorCode <= 0)
    {
        char buffer[200];
        mbedtls_strerror(errorCode, buffer, 200);
        fprintf(stderr, "ASN.1 Encode: Last error was: %d - %s\n", errorCode, buffer);
    }
    return errorCode;
}

int qo_asn1_encode_ecx_25519(unsigned char **pOutput, const uint8_t *pSrc, size_t length)
{
    // We start by allocating a large enough vector so that the preamble and the key can be stored.
    // This temp buffer will then be copied to pOutput with exact size after calculating/accumulating the actual size.
    std::vector<uint8_t> buffer(length*2);
    // Mbedtls asn1 encoding starts working from the end of the buffer, hence we write the last component, the private key, first.
    // As we move from back to front, we accumulate the bytes we have written in total_length
    auto total_length = 0;
    uint8_t* pCurrent = &buffer.back();
    uint8_t* pStart = buffer.data();

    // Here goes the OCTET_STRING + length + private key
    int rv = CheckAsn1EncodeError(mbedtls_asn1_write_octet_string(&pCurrent, pStart, pSrc, length));
    if (rv <= 0)
    {
        return rv;
    }
    total_length += rv;

    // We append OCTET_STRING tag + len again, openssl use this to isolate private key
    // Here goes OCTET_STRING + length, remember in reverse order, which also helps with accumulating the nof bytes written
    rv = CheckAsn1EncodeError(mbedtls_asn1_write_len(&pCurrent, pStart, total_length));
    if (rv <= 0)
    {
        return rv;
    }
    total_length += rv;

    rv = CheckAsn1EncodeError(mbedtls_asn1_write_tag(&pCurrent, pStart, MBEDTLS_ASN1_OCTET_STRING));
    if (rv <= 0)
    {
        return rv;
    }
    total_length += rv;

    // Here goes OID + length + encoded_oid (3 bytes)
    // TODO: Find a better way to get the encoded oid string of 1.3.101.110, the 3 bytes that represents this is 2b 65 6e
    const char* oid = "\x2b\x65\x6e";
    size_t oid_len = strlen(oid);
    rv= CheckAsn1EncodeError(mbedtls_asn1_write_oid(&pCurrent, pStart, oid, oid_len));
    if (rv <= 0)
    {
        return rv;
    }
    total_length += rv;

    // Note here we are writing the previous rv as the length, as write_oid() will write 0x06 0x03 0x2b 0x65 0x6e, 5 bytes in total
    rv = CheckAsn1EncodeError(mbedtls_asn1_write_len(&pCurrent, pStart, rv));
    if (rv <= 0)
    {
        return rv;
    }
    total_length += rv;

    // This is the sequence that encloses the oid above.
    rv = CheckAsn1EncodeError(mbedtls_asn1_write_tag(&pCurrent, pStart, MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED));
    if (rv <= 0)
    {
        return rv;
    }
    total_length += rv;

    // Here goes the INTEGER value zero
    rv = CheckAsn1EncodeError(mbedtls_asn1_write_int(&pCurrent, pStart, 0 )); // an integer whose value is zero
    if (rv <= 0)
    {
        return rv;
    }
    total_length += rv;

    // Note that we are writing the total_length here but then continue writing the starting tag.
    // At the end, encoded content length will be larger than the value written at this point.
    rv = CheckAsn1EncodeError(mbedtls_asn1_write_len(&pCurrent, pStart, total_length));
    if (rv <= 0)
    {
        return rv;
    }
    total_length += rv;

    // The starting tag of the preamble.
    rv = CheckAsn1EncodeError(mbedtls_asn1_write_tag(&pCurrent, pStart, MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED));
    if (rv <= 0)
    {
        return rv;
    }
    total_length += rv;

    // We now have the actual encoded content length, which we can use to allocate pOutput and copy from buffer's relevant point
    *pOutput = (uint8_t*) calloc(sizeof(uint8_t),total_length);
    if(*pOutput == nullptr)
    {
        return ASN1_ENCODE_ALLOC_FAILURE;
    }

    // Note that the encoded content is located to the end of the package, hence we start to copy from (end - total_length)
    memcpy(*pOutput, &buffer.back()-total_length, total_length );

    return total_length;
}
