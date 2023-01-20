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

#ifndef QO_DECRYPT_QO_ASN1_DECODE_H
#define QO_DECRYPT_QO_ASN1_DECODE_H


#define ASN1_DECODE_SUCCESS 0
#define ASN1_DECODE_ALLOC_FAILURE -1

// ****************************************************************************
// This ASN1 decoder is specialised to decode PQ Key payload from QO API
// Expecting to get an ASN1 sequence, which contains 2 octet strings.
// ****************************************************************************
extern int qo_asn1_decode_pqc(unsigned char *p, size_t plen, uint8_t **pubKey, size_t *publen, uint8_t **privKey, size_t *privlen);


// ****************************************************************************
// This ASN1 decoder is specialised to decode ECX Key payload from QO API
//
// https://www.secg.org/sec1-v2.pdf - Section C.4
//     RFC 5915, or SEC1 Appendix C.4
//
//     ECPrivateKey ::= SEQUENCE {
//          version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
//          privateKey     OCTET STRING,
//          parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
//          publicKey  [1] BIT STRING OPTIONAL
//        }
// ****************************************************************************
extern int qo_asn1_decode_ecx(unsigned char *p, size_t plen, uint8_t **pDestPubKey, size_t *pDestPubKeyLen, uint8_t **privKey, size_t *privlen);

#endif //QO_DECRYPT_QO_ASN1_DECODE_H
