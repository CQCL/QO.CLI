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
#ifndef QO_DECRYPT_QO_ASN1_ENCODE_H
#define QO_DECRYPT_QO_ASN1_ENCODE_H

#define ASN1_ENCODE_ALLOC_FAILURE -2
/*
 * This is how X25519 is encoded by openssl, we will match this encoding so that the keys we output are
 * usable(derive public key from) by openssl

SEQUENCE {
    INTEGER 0x00 (0 decimal)
    SEQUENCE {
        OBJECTIDENTIFIER 1.3.101.110
    }
    OCTETSTRING 0420e0b58c685c915c0fe56e44283f793ddfe854918975528d2a7109127567407c64
}
*/
/**
 * Encode the given private X25519 key in ASN1 form, so that openssl can derive public key
 * @param pOutput resulting ASN1 encoded buffer, malloc'ed within the function
 * @param pSrc the buffer that contains the private key
 * @param length the length of the private key
 * @return negative error value or the total length of the encoded content.
 */
extern int qo_asn1_encode_ecx_25519(unsigned char **pOutput, const uint8_t *pSrc, size_t length);

#endif //QO_DECRYPT_QO_ASN1_ENCODE_H
