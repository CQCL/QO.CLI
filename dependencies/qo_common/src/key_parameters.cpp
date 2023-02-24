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
#include "qo_common/key_parameters.h"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <stdexcept>
#include <unordered_map>

namespace Quantinuum::QuantumOrigin::Common
{
    const std::unordered_map<VariantType, VariantValue> typeVariantNames = {
        {                                  Cli_AES_Variant::AES_128,                                      {"AES", 128}},
        {                                  Cli_AES_Variant::AES_192,                                      {"AES", 192}},
        {                                  Cli_AES_Variant::AES_256,                                      {"AES", 256}},
        {                                 Cli_RSA_Variant::RSA_2048,                                     {"RSA", 2048}},
        {                                 Cli_RSA_Variant::RSA_3072,                                     {"RSA", 3072}},
        {                                 Cli_RSA_Variant::RSA_4096,                                     {"RSA", 4096}},
        {                                   Cli_EC_Variant::BP256R1,                                 {"EC", "Bp256r1"}},
        {                                   Cli_EC_Variant::BP384R1,                                 {"EC", "Bp384r1"}},
        {                                   Cli_EC_Variant::BP512R1,                                 {"EC", "Bp512r1"}},
        {                                 Cli_EC_Variant::SECP192K1,                               {"EC", "SecP192k1"}},
        {                                 Cli_EC_Variant::SECP192R1,                               {"EC", "SecP192r1"}},
        {                                 Cli_EC_Variant::SECP224K1,                               {"EC", "SecP224k1"}},
        {                                 Cli_EC_Variant::SECP224R1,                               {"EC", "SecP224r1"}},
        {                                 Cli_EC_Variant::SECP256K1,                               {"EC", "SecP256k1"}},
        {                                 Cli_EC_Variant::SECP256R1,                               {"EC", "SecP256r1"}},
        {                                 Cli_EC_Variant::SECP384R1,                               {"EC", "SecP384r1"}},
        {                                 Cli_EC_Variant::SECP521R1,                               {"EC", "SecP521r1"}},
        {                                    Cli_EC_Variant::X25519,                                  {"EC", "X25519"}},
        {                           Cli_PQ_KEM_Variant::KEM_BIKE_L1,                               {"BIKE", "BIKE-L1"}},
        {                           Cli_PQ_KEM_Variant::KEM_BIKE_L3,                               {"BIKE", "BIKE-L3"}},
        {                           Cli_PQ_KEM_Variant::KEM_HQC_128,                                {"HQC", "HQC-128"}},
        {                           Cli_PQ_KEM_Variant::KEM_HQC_192,                                {"HQC", "HQC-192"}},
        {                           Cli_PQ_KEM_Variant::KEM_HQC_256,                                {"HQC", "HQC-256"}},
        {                     Cli_PQ_KEM_Variant::KEM_KYBER_768_90S,                         {"KYBER", "KYBER768-90s"}},
        {                         Cli_PQ_KEM_Variant::KEM_KYBER_768,                             {"KYBER", "KYBER768"}},
        {                        Cli_PQ_KEM_Variant::KEM_KYBER_1024,                            {"KYBER", "KYBER1024"}},
        {                         Cli_PQ_KEM_Variant::KEM_KYBER_512,                             {"KYBER", "KYBER512"}},
        {                     Cli_PQ_KEM_Variant::KEM_KYBER_512_90S,                         {"KYBER", "KYBER512-90s"}},
        {                    Cli_PQ_KEM_Variant::KEM_KYBER_1024_90S,                        {"KYBER", "KYBER1024-90s"}},
        {                   Cli_PQ_KEM_Variant::KEM_MCELIECE_348864,   {"CLASSIC-MCELIECE", "CLASSIC-MCELIECE-348864"}},
        {                  Cli_PQ_KEM_Variant::KEM_MCELIECE_348864F,  {"CLASSIC-MCELIECE", "CLASSIC-MCELIECE-348864f"}},
        {                   Cli_PQ_KEM_Variant::KEM_MCELIECE_460896,   {"CLASSIC-MCELIECE", "CLASSIC-MCELIECE-460896"}},
        {                  Cli_PQ_KEM_Variant::KEM_MCELIECE_460896F,  {"CLASSIC-MCELIECE", "CLASSIC-MCELIECE-460896f"}},
        {                  Cli_PQ_KEM_Variant::KEM_MCELIECE_6688128,  {"CLASSIC-MCELIECE", "CLASSIC-MCELIECE-6688128"}},
        {                 Cli_PQ_KEM_Variant::KEM_MCELIECE_6688128F, {"CLASSIC-MCELIECE", "CLASSIC-MCELIECE-6688128f"}},
        {                  Cli_PQ_KEM_Variant::KEM_MCELIECE_6960119,  {"CLASSIC-MCELIECE", "CLASSIC-MCELIECE-6960119"}},
        {                 Cli_PQ_KEM_Variant::KEM_MCELIECE_6960119F, {"CLASSIC-MCELIECE", "CLASSIC-MCELIECE-6960119f"}},
        {                  Cli_PQ_KEM_Variant::KEM_MCELIECE_8192128,  {"CLASSIC-MCELIECE", "CLASSIC-MCELIECE-8192128"}},
        {                 Cli_PQ_KEM_Variant::KEM_MCELIECE_8192128F, {"CLASSIC-MCELIECE", "CLASSIC-MCELIECE-8192128f"}},
        {                       Cli_PQ_KEM_Variant::KEM_NTRULPR_653,                     {"NTRU-PRIME", "NTRULPR-653"}},
        {                       Cli_PQ_KEM_Variant::KEM_NTRULPR_761,                     {"NTRU-PRIME", "NTRULPR-761"}},
        {                       Cli_PQ_KEM_Variant::KEM_NTRULPR_857,                     {"NTRU-PRIME", "NTRULPR-857"}},
        {                      Cli_PQ_KEM_Variant::KEM_NTRULPR_1277,                    {"NTRU-PRIME", "NTRULPR-1277"}},
        {                        Cli_PQ_KEM_Variant::KEM_SNTRUP_653,                      {"NTRU-PRIME", "SNTRUP-653"}},
        {                        Cli_PQ_KEM_Variant::KEM_SNTRUP_761,                      {"NTRU-PRIME", "SNTRUP-761"}},
        {                        Cli_PQ_KEM_Variant::KEM_SNTRUP_857,                      {"NTRU-PRIME", "SNTRUP-857"}},
        {                       Cli_PQ_KEM_Variant::KEM_SNTRUP_1277,                     {"NTRU-PRIME", "SNTRUP-1277"}},
        {                  Cli_PQ_Signature_Variant::SIG_DILITHIUM2,                       {"DILITHIUM", "DILITHIUM2"}},
        {              Cli_PQ_Signature_Variant::SIG_DILITHIUM2_AES,                   {"DILITHIUM", "DILITHIUM2-AES"}},
        {                  Cli_PQ_Signature_Variant::SIG_DILITHIUM3,                       {"DILITHIUM", "DILITHIUM3"}},
        {              Cli_PQ_Signature_Variant::SIG_DILITHIUM3_AES,                   {"DILITHIUM", "DILITHIUM3-AES"}},
        {                  Cli_PQ_Signature_Variant::SIG_DILITHIUM5,                       {"DILITHIUM", "DILITHIUM5"}},
        {              Cli_PQ_Signature_Variant::SIG_DILITHIUM5_AES,                   {"DILITHIUM", "DILITHIUM5-AES"}},
        {                  Cli_PQ_Signature_Variant::SIG_FALCON_512,                          {"FALCON", "FALCON-512"}},
        {                 Cli_PQ_Signature_Variant::SIG_FALCON_1024,                         {"FALCON", "FALCON-1024"}},
        {  Cli_PQ_Signature_Variant::SIG_SPHINCS_HARAKA_128F_ROBUST,         {"SPHINCS", "SPHINCS-HARAKA-128F-ROBUST"}},
        {  Cli_PQ_Signature_Variant::SIG_SPHINCS_HARAKA_128F_SIMPLE,         {"SPHINCS", "SPHINCS-HARAKA-128F-SIMPLE"}},
        {  Cli_PQ_Signature_Variant::SIG_SPHINCS_HARAKA_128S_ROBUST,         {"SPHINCS", "SPHINCS-HARAKA-128S-ROBUST"}},
        {  Cli_PQ_Signature_Variant::SIG_SPHINCS_HARAKA_128S_SIMPLE,         {"SPHINCS", "SPHINCS-HARAKA-128S-SIMPLE"}},
        {  Cli_PQ_Signature_Variant::SIG_SPHINCS_HARAKA_192F_ROBUST,         {"SPHINCS", "SPHINCS-HARAKA-192F-ROBUST"}},
        {  Cli_PQ_Signature_Variant::SIG_SPHINCS_HARAKA_192F_SIMPLE,         {"SPHINCS", "SPHINCS-HARAKA-192F-SIMPLE"}},
        {  Cli_PQ_Signature_Variant::SIG_SPHINCS_HARAKA_192S_ROBUST,         {"SPHINCS", "SPHINCS-HARAKA-192S-ROBUST"}},
        {  Cli_PQ_Signature_Variant::SIG_SPHINCS_HARAKA_192S_SIMPLE,         {"SPHINCS", "SPHINCS-HARAKA-192S-SIMPLE"}},
        {  Cli_PQ_Signature_Variant::SIG_SPHINCS_HARAKA_256F_ROBUST,         {"SPHINCS", "SPHINCS-HARAKA-256F-ROBUST"}},
        {  Cli_PQ_Signature_Variant::SIG_SPHINCS_HARAKA_256F_SIMPLE,         {"SPHINCS", "SPHINCS-HARAKA-256F-SIMPLE"}},
        {  Cli_PQ_Signature_Variant::SIG_SPHINCS_HARAKA_256S_ROBUST,         {"SPHINCS", "SPHINCS-HARAKA-256S-ROBUST"}},
        {  Cli_PQ_Signature_Variant::SIG_SPHINCS_HARAKA_256S_SIMPLE,         {"SPHINCS", "SPHINCS-HARAKA-256S-SIMPLE"}},
        {  Cli_PQ_Signature_Variant::SIG_SPHINCS_SHA256_128F_ROBUST,         {"SPHINCS", "SPHINCS-SHA256-128F-ROBUST"}},
        {  Cli_PQ_Signature_Variant::SIG_SPHINCS_SHA256_128F_SIMPLE,         {"SPHINCS", "SPHINCS-SHA256-128F-SIMPLE"}},
        {  Cli_PQ_Signature_Variant::SIG_SPHINCS_SHA256_128S_ROBUST,         {"SPHINCS", "SPHINCS-SHA256-128S-ROBUST"}},
        {  Cli_PQ_Signature_Variant::SIG_SPHINCS_SHA256_128S_SIMPLE,         {"SPHINCS", "SPHINCS-SHA256-128S-SIMPLE"}},
        {  Cli_PQ_Signature_Variant::SIG_SPHINCS_SHA256_192F_ROBUST,         {"SPHINCS", "SPHINCS-SHA256-192F-ROBUST"}},
        {  Cli_PQ_Signature_Variant::SIG_SPHINCS_SHA256_192F_SIMPLE,         {"SPHINCS", "SPHINCS-SHA256-192F-SIMPLE"}},
        {  Cli_PQ_Signature_Variant::SIG_SPHINCS_SHA256_192S_ROBUST,         {"SPHINCS", "SPHINCS-SHA256-192S-ROBUST"}},
        {  Cli_PQ_Signature_Variant::SIG_SPHINCS_SHA256_192S_SIMPLE,         {"SPHINCS", "SPHINCS-SHA256-192S-SIMPLE"}},
        {  Cli_PQ_Signature_Variant::SIG_SPHINCS_SHA256_256F_ROBUST,         {"SPHINCS", "SPHINCS-SHA256-256F-ROBUST"}},
        {  Cli_PQ_Signature_Variant::SIG_SPHINCS_SHA256_256F_SIMPLE,         {"SPHINCS", "SPHINCS-SHA256-256F-SIMPLE"}},
        {  Cli_PQ_Signature_Variant::SIG_SPHINCS_SHA256_256S_ROBUST,         {"SPHINCS", "SPHINCS-SHA256-256S-ROBUST"}},
        {  Cli_PQ_Signature_Variant::SIG_SPHINCS_SHA256_256S_SIMPLE,         {"SPHINCS", "SPHINCS-SHA256-256S-SIMPLE"}},
        {Cli_PQ_Signature_Variant::SIG_SPHINCS_SHAKE256_128F_ROBUST,       {"SPHINCS", "SPHINCS-SHAKE256-128F-ROBUST"}},
        {Cli_PQ_Signature_Variant::SIG_SPHINCS_SHAKE256_128F_SIMPLE,       {"SPHINCS", "SPHINCS-SHAKE256-128F-SIMPLE"}},
        {Cli_PQ_Signature_Variant::SIG_SPHINCS_SHAKE256_128S_ROBUST,       {"SPHINCS", "SPHINCS-SHAKE256-128S-ROBUST"}},
        {Cli_PQ_Signature_Variant::SIG_SPHINCS_SHAKE256_128S_SIMPLE,       {"SPHINCS", "SPHINCS-SHAKE256-128S-SIMPLE"}},
        {Cli_PQ_Signature_Variant::SIG_SPHINCS_SHAKE256_192F_ROBUST,       {"SPHINCS", "SPHINCS-SHAKE256-192F-ROBUST"}},
        {Cli_PQ_Signature_Variant::SIG_SPHINCS_SHAKE256_192F_SIMPLE,       {"SPHINCS", "SPHINCS-SHAKE256-192F-SIMPLE"}},
        {Cli_PQ_Signature_Variant::SIG_SPHINCS_SHAKE256_192S_ROBUST,       {"SPHINCS", "SPHINCS-SHAKE256-192S-ROBUST"}},
        {Cli_PQ_Signature_Variant::SIG_SPHINCS_SHAKE256_192S_SIMPLE,       {"SPHINCS", "SPHINCS-SHAKE256-192S-SIMPLE"}},
        {Cli_PQ_Signature_Variant::SIG_SPHINCS_SHAKE256_256F_ROBUST,       {"SPHINCS", "SPHINCS-SHAKE256-256F-ROBUST"}},
        {Cli_PQ_Signature_Variant::SIG_SPHINCS_SHAKE256_256F_SIMPLE,       {"SPHINCS", "SPHINCS-SHAKE256-256F-SIMPLE"}},
        {Cli_PQ_Signature_Variant::SIG_SPHINCS_SHAKE256_256S_ROBUST,       {"SPHINCS", "SPHINCS-SHAKE256-256S-ROBUST"}},
        {Cli_PQ_Signature_Variant::SIG_SPHINCS_SHAKE256_256S_SIMPLE,       {"SPHINCS", "SPHINCS-SHAKE256-256S-SIMPLE"}}
    };

    const std::unordered_map<std::string, KeyType> supportedKeyTypes = {
        {                        "RAND",                               {Cli_Alg_Type::KEY_TYPE_RAND, Cli_Rand_Variant::VARIANT_RAND}},
        {                     "AES-128",                                      {Cli_Alg_Type::KEY_TYPE_AES, Cli_AES_Variant::AES_128}},
        {                     "AES-192",                                      {Cli_Alg_Type::KEY_TYPE_AES, Cli_AES_Variant::AES_192}},
        {                     "AES-256",                                      {Cli_Alg_Type::KEY_TYPE_AES, Cli_AES_Variant::AES_256}},

        {                    "RSA-2048",                                     {Cli_Alg_Type::KEY_TYPE_RSA, Cli_RSA_Variant::RSA_2048}},
        {                    "RSA-3072",                                     {Cli_Alg_Type::KEY_TYPE_RSA, Cli_RSA_Variant::RSA_3072}},
        {                    "RSA-4096",                                     {Cli_Alg_Type::KEY_TYPE_RSA, Cli_RSA_Variant::RSA_4096}},

        {                  "EC-BP256R1",                                        {Cli_Alg_Type::KEY_TYPE_EC, Cli_EC_Variant::BP256R1}},
        {                  "EC-BP384R1",                                        {Cli_Alg_Type::KEY_TYPE_EC, Cli_EC_Variant::BP384R1}},
        {                  "EC-BP512R1",                                        {Cli_Alg_Type::KEY_TYPE_EC, Cli_EC_Variant::BP512R1}},
        {                "EC-SECP192K1",                                      {Cli_Alg_Type::KEY_TYPE_EC, Cli_EC_Variant::SECP192K1}},
        {                "EC-SECP192R1",                                      {Cli_Alg_Type::KEY_TYPE_EC, Cli_EC_Variant::SECP192R1}},
        {                "EC-SECP224K1",                                      {Cli_Alg_Type::KEY_TYPE_EC, Cli_EC_Variant::SECP224K1}},
        {                "EC-SECP224R1",                                      {Cli_Alg_Type::KEY_TYPE_EC, Cli_EC_Variant::SECP224R1}},
        {                "EC-SECP256K1",                                      {Cli_Alg_Type::KEY_TYPE_EC, Cli_EC_Variant::SECP256K1}},
        {                "EC-SECP256R1",                                      {Cli_Alg_Type::KEY_TYPE_EC, Cli_EC_Variant::SECP256R1}},
        {                "EC-SECP384R1",                                      {Cli_Alg_Type::KEY_TYPE_EC, Cli_EC_Variant::SECP384R1}},
        {                "EC-SECP521R1",                                      {Cli_Alg_Type::KEY_TYPE_EC, Cli_EC_Variant::SECP521R1}},
        {                   "EC-X25519",                                         {Cli_Alg_Type::KEY_TYPE_EC, Cli_EC_Variant::X25519}},

        {                       "SABER",                              {Cli_Alg_Type::KEY_TYPE_PQ_KEM, Cli_PQ_KEM_Variant::KEM_SABER}},
        {                   "FIRESABER",                          {Cli_Alg_Type::KEY_TYPE_PQ_KEM, Cli_PQ_KEM_Variant::KEM_FIRESABER}},
        {                  "LIGHTSABER",                         {Cli_Alg_Type::KEY_TYPE_PQ_KEM, Cli_PQ_KEM_Variant::KEM_LIGHTSABER}},
        {     "CLASSIC-MCELIECE-348864",                    {Cli_Alg_Type::KEY_TYPE_PQ_KEM, Cli_PQ_KEM_Variant::KEM_MCELIECE_348864}},
        {    "CLASSIC-MCELIECE-348864F",                   {Cli_Alg_Type::KEY_TYPE_PQ_KEM, Cli_PQ_KEM_Variant::KEM_MCELIECE_348864F}},
        {     "CLASSIC-MCELIECE-460896",                    {Cli_Alg_Type::KEY_TYPE_PQ_KEM, Cli_PQ_KEM_Variant::KEM_MCELIECE_460896}},
        {    "CLASSIC-MCELIECE-460896F",                   {Cli_Alg_Type::KEY_TYPE_PQ_KEM, Cli_PQ_KEM_Variant::KEM_MCELIECE_460896F}},
        {    "CLASSIC-MCELIECE-6688128",                   {Cli_Alg_Type::KEY_TYPE_PQ_KEM, Cli_PQ_KEM_Variant::KEM_MCELIECE_6688128}},
        {   "CLASSIC-MCELIECE-6688128F",                  {Cli_Alg_Type::KEY_TYPE_PQ_KEM, Cli_PQ_KEM_Variant::KEM_MCELIECE_6688128F}},
        {    "CLASSIC-MCELIECE-6960119",                   {Cli_Alg_Type::KEY_TYPE_PQ_KEM, Cli_PQ_KEM_Variant::KEM_MCELIECE_6960119}},
        {   "CLASSIC-MCELIECE-6960119F",                  {Cli_Alg_Type::KEY_TYPE_PQ_KEM, Cli_PQ_KEM_Variant::KEM_MCELIECE_6960119F}},
        {    "CLASSIC-MCELIECE-8192128",                   {Cli_Alg_Type::KEY_TYPE_PQ_KEM, Cli_PQ_KEM_Variant::KEM_MCELIECE_8192128}},
        {   "CLASSIC-MCELIECE-8192128F",                  {Cli_Alg_Type::KEY_TYPE_PQ_KEM, Cli_PQ_KEM_Variant::KEM_MCELIECE_8192128F}},
        {                    "KYBER512",                          {Cli_Alg_Type::KEY_TYPE_PQ_KEM, Cli_PQ_KEM_Variant::KEM_KYBER_512}},
        {                "KYBER512-90S",                      {Cli_Alg_Type::KEY_TYPE_PQ_KEM, Cli_PQ_KEM_Variant::KEM_KYBER_512_90S}},
        {                   "KYBER1024",                         {Cli_Alg_Type::KEY_TYPE_PQ_KEM, Cli_PQ_KEM_Variant::KEM_KYBER_1024}},
        {               "KYBER1024-90S",                     {Cli_Alg_Type::KEY_TYPE_PQ_KEM, Cli_PQ_KEM_Variant::KEM_KYBER_1024_90S}},
        {                    "KYBER768",                          {Cli_Alg_Type::KEY_TYPE_PQ_KEM, Cli_PQ_KEM_Variant::KEM_KYBER_768}},
        {                "KYBER768-90S",                      {Cli_Alg_Type::KEY_TYPE_PQ_KEM, Cli_PQ_KEM_Variant::KEM_KYBER_768_90S}},
        {               "NTRU-2048-509",                      {Cli_Alg_Type::KEY_TYPE_PQ_KEM, Cli_PQ_KEM_Variant::KEM_NTRU_2048_509}},
        {               "NTRU-2048-677",                      {Cli_Alg_Type::KEY_TYPE_PQ_KEM, Cli_PQ_KEM_Variant::KEM_NTRU_2048_677}},
        {               "NTRU-4096-821",                      {Cli_Alg_Type::KEY_TYPE_PQ_KEM, Cli_PQ_KEM_Variant::KEM_NTRU_4096_821}},
        {               "NTRU-HRSS-701",                      {Cli_Alg_Type::KEY_TYPE_PQ_KEM, Cli_PQ_KEM_Variant::KEM_NTRU_HRSS_701}},
        {                 "NTRULPR-653",                        {Cli_Alg_Type::KEY_TYPE_PQ_KEM, Cli_PQ_KEM_Variant::KEM_NTRULPR_653}},
        {                 "NTRULPR-761",                        {Cli_Alg_Type::KEY_TYPE_PQ_KEM, Cli_PQ_KEM_Variant::KEM_NTRULPR_761}},
        {                 "NTRULPR-857",                        {Cli_Alg_Type::KEY_TYPE_PQ_KEM, Cli_PQ_KEM_Variant::KEM_NTRULPR_857}},
        {                "NTRULPR-1277",                       {Cli_Alg_Type::KEY_TYPE_PQ_KEM, Cli_PQ_KEM_Variant::KEM_NTRULPR_1277}},
        {                  "SNTRUP-653",                         {Cli_Alg_Type::KEY_TYPE_PQ_KEM, Cli_PQ_KEM_Variant::KEM_SNTRUP_653}},
        {                  "SNTRUP-761",                         {Cli_Alg_Type::KEY_TYPE_PQ_KEM, Cli_PQ_KEM_Variant::KEM_SNTRUP_761}},
        {                  "SNTRUP-857",                         {Cli_Alg_Type::KEY_TYPE_PQ_KEM, Cli_PQ_KEM_Variant::KEM_SNTRUP_857}},
        {                 "SNTRUP-1277",                        {Cli_Alg_Type::KEY_TYPE_PQ_KEM, Cli_PQ_KEM_Variant::KEM_SNTRUP_1277}},
        {                     "HQC-128",                            {Cli_Alg_Type::KEY_TYPE_PQ_KEM, Cli_PQ_KEM_Variant::KEM_HQC_128}},
        {                     "HQC-192",                            {Cli_Alg_Type::KEY_TYPE_PQ_KEM, Cli_PQ_KEM_Variant::KEM_HQC_192}},
        {                     "HQC-256",                            {Cli_Alg_Type::KEY_TYPE_PQ_KEM, Cli_PQ_KEM_Variant::KEM_HQC_256}},
        {                     "BIKE-L1",                            {Cli_Alg_Type::KEY_TYPE_PQ_KEM, Cli_PQ_KEM_Variant::KEM_BIKE_L1}},
        {                     "BIKE-L3",                            {Cli_Alg_Type::KEY_TYPE_PQ_KEM, Cli_PQ_KEM_Variant::KEM_BIKE_L3}},

        {                  "DILITHIUM2",                   {Cli_Alg_Type::KEY_TYPE_PQ_SIG, Cli_PQ_Signature_Variant::SIG_DILITHIUM2}},
        {                  "DILITHIUM3",                   {Cli_Alg_Type::KEY_TYPE_PQ_SIG, Cli_PQ_Signature_Variant::SIG_DILITHIUM3}},
        {                  "DILITHIUM5",                   {Cli_Alg_Type::KEY_TYPE_PQ_SIG, Cli_PQ_Signature_Variant::SIG_DILITHIUM5}},
        {              "DILITHIUM2-AES",               {Cli_Alg_Type::KEY_TYPE_PQ_SIG, Cli_PQ_Signature_Variant::SIG_DILITHIUM2_AES}},
        {              "DILITHIUM3-AES",               {Cli_Alg_Type::KEY_TYPE_PQ_SIG, Cli_PQ_Signature_Variant::SIG_DILITHIUM3_AES}},
        {              "DILITHIUM5-AES",               {Cli_Alg_Type::KEY_TYPE_PQ_SIG, Cli_PQ_Signature_Variant::SIG_DILITHIUM5_AES}},
        {           "RAINBOW-I-CLASSIC",            {Cli_Alg_Type::KEY_TYPE_PQ_SIG, Cli_PQ_Signature_Variant::SIG_RAINBOW_I_CLASSIC}},
        {    "RAINBOW-I-CIRCUMZENITHAL",     {Cli_Alg_Type::KEY_TYPE_PQ_SIG, Cli_PQ_Signature_Variant::SIG_RAINBOW_I_CIRCUMZENITHAL}},
        {        "RAINBOW-I-COMPRESSED",         {Cli_Alg_Type::KEY_TYPE_PQ_SIG, Cli_PQ_Signature_Variant::SIG_RAINBOW_I_COMPRESSED}},
        {         "RAINBOW-III-CLASSIC",          {Cli_Alg_Type::KEY_TYPE_PQ_SIG, Cli_PQ_Signature_Variant::SIG_RAINBOW_III_CLASSIC}},
        {  "RAINBOW-III-CIRCUMZENITHAL",   {Cli_Alg_Type::KEY_TYPE_PQ_SIG, Cli_PQ_Signature_Variant::SIG_RAINBOW_III_CIRCUMZENITHAL}},
        {      "RAINBOW-III-COMPRESSED",       {Cli_Alg_Type::KEY_TYPE_PQ_SIG, Cli_PQ_Signature_Variant::SIG_RAINBOW_III_COMPRESSED}},
        {           "RAINBOW-V-CLASSIC",            {Cli_Alg_Type::KEY_TYPE_PQ_SIG, Cli_PQ_Signature_Variant::SIG_RAINBOW_V_CLASSIC}},
        {    "RAINBOW-V-CIRCUMZENITHAL",     {Cli_Alg_Type::KEY_TYPE_PQ_SIG, Cli_PQ_Signature_Variant::SIG_RAINBOW_V_CIRCUMZENITHAL}},
        {        "RAINBOW-V-COMPRESSED",         {Cli_Alg_Type::KEY_TYPE_PQ_SIG, Cli_PQ_Signature_Variant::SIG_RAINBOW_V_COMPRESSED}},
        {                  "FALCON-512",                   {Cli_Alg_Type::KEY_TYPE_PQ_SIG, Cli_PQ_Signature_Variant::SIG_FALCON_512}},
        {                 "FALCON-1024",                  {Cli_Alg_Type::KEY_TYPE_PQ_SIG, Cli_PQ_Signature_Variant::SIG_FALCON_1024}},
        {  "SPHINCS-HARAKA-128F-ROBUST",   {Cli_Alg_Type::KEY_TYPE_PQ_SIG, Cli_PQ_Signature_Variant::SIG_SPHINCS_HARAKA_128F_ROBUST}},
        {  "SPHINCS-HARAKA-128F-SIMPLE",   {Cli_Alg_Type::KEY_TYPE_PQ_SIG, Cli_PQ_Signature_Variant::SIG_SPHINCS_HARAKA_128F_SIMPLE}},
        {  "SPHINCS-HARAKA-128S-ROBUST",   {Cli_Alg_Type::KEY_TYPE_PQ_SIG, Cli_PQ_Signature_Variant::SIG_SPHINCS_HARAKA_128S_ROBUST}},
        {  "SPHINCS-HARAKA-128S-SIMPLE",   {Cli_Alg_Type::KEY_TYPE_PQ_SIG, Cli_PQ_Signature_Variant::SIG_SPHINCS_HARAKA_128S_SIMPLE}},
        {  "SPHINCS-HARAKA-192F-ROBUST",   {Cli_Alg_Type::KEY_TYPE_PQ_SIG, Cli_PQ_Signature_Variant::SIG_SPHINCS_HARAKA_192F_ROBUST}},
        {  "SPHINCS-HARAKA-192F-SIMPLE",   {Cli_Alg_Type::KEY_TYPE_PQ_SIG, Cli_PQ_Signature_Variant::SIG_SPHINCS_HARAKA_192F_SIMPLE}},
        {  "SPHINCS-HARAKA-192S-ROBUST",   {Cli_Alg_Type::KEY_TYPE_PQ_SIG, Cli_PQ_Signature_Variant::SIG_SPHINCS_HARAKA_192S_ROBUST}},
        {  "SPHINCS-HARAKA-192S-SIMPLE",   {Cli_Alg_Type::KEY_TYPE_PQ_SIG, Cli_PQ_Signature_Variant::SIG_SPHINCS_HARAKA_192S_SIMPLE}},
        {  "SPHINCS-HARAKA-256F-ROBUST",   {Cli_Alg_Type::KEY_TYPE_PQ_SIG, Cli_PQ_Signature_Variant::SIG_SPHINCS_HARAKA_256F_ROBUST}},
        {  "SPHINCS-HARAKA-256F-SIMPLE",   {Cli_Alg_Type::KEY_TYPE_PQ_SIG, Cli_PQ_Signature_Variant::SIG_SPHINCS_HARAKA_256F_SIMPLE}},
        {  "SPHINCS-HARAKA-256S-ROBUST",   {Cli_Alg_Type::KEY_TYPE_PQ_SIG, Cli_PQ_Signature_Variant::SIG_SPHINCS_HARAKA_256S_ROBUST}},
        {  "SPHINCS-HARAKA-256S-SIMPLE",   {Cli_Alg_Type::KEY_TYPE_PQ_SIG, Cli_PQ_Signature_Variant::SIG_SPHINCS_HARAKA_256S_SIMPLE}},
        {  "SPHINCS-SHA256-128F-ROBUST",   {Cli_Alg_Type::KEY_TYPE_PQ_SIG, Cli_PQ_Signature_Variant::SIG_SPHINCS_SHA256_128F_ROBUST}},
        {  "SPHINCS-SHA256-128F-SIMPLE",   {Cli_Alg_Type::KEY_TYPE_PQ_SIG, Cli_PQ_Signature_Variant::SIG_SPHINCS_SHA256_128F_SIMPLE}},
        {  "SPHINCS-SHA256-128S-ROBUST",   {Cli_Alg_Type::KEY_TYPE_PQ_SIG, Cli_PQ_Signature_Variant::SIG_SPHINCS_SHA256_128S_ROBUST}},
        {  "SPHINCS-SHA256-128S-SIMPLE",   {Cli_Alg_Type::KEY_TYPE_PQ_SIG, Cli_PQ_Signature_Variant::SIG_SPHINCS_SHA256_128S_SIMPLE}},
        {  "SPHINCS-SHA256-192F-ROBUST",   {Cli_Alg_Type::KEY_TYPE_PQ_SIG, Cli_PQ_Signature_Variant::SIG_SPHINCS_SHA256_192F_ROBUST}},
        {  "SPHINCS-SHA256-192F-SIMPLE",   {Cli_Alg_Type::KEY_TYPE_PQ_SIG, Cli_PQ_Signature_Variant::SIG_SPHINCS_SHA256_192F_SIMPLE}},
        {  "SPHINCS-SHA256-192S-ROBUST",   {Cli_Alg_Type::KEY_TYPE_PQ_SIG, Cli_PQ_Signature_Variant::SIG_SPHINCS_SHA256_192S_ROBUST}},
        {  "SPHINCS-SHA256-192S-SIMPLE",   {Cli_Alg_Type::KEY_TYPE_PQ_SIG, Cli_PQ_Signature_Variant::SIG_SPHINCS_SHA256_192S_SIMPLE}},
        {  "SPHINCS-SHA256-256F-ROBUST",   {Cli_Alg_Type::KEY_TYPE_PQ_SIG, Cli_PQ_Signature_Variant::SIG_SPHINCS_SHA256_256F_ROBUST}},
        {  "SPHINCS-SHA256-256F-SIMPLE",   {Cli_Alg_Type::KEY_TYPE_PQ_SIG, Cli_PQ_Signature_Variant::SIG_SPHINCS_SHA256_256F_SIMPLE}},
        {  "SPHINCS-SHA256-256S-ROBUST",   {Cli_Alg_Type::KEY_TYPE_PQ_SIG, Cli_PQ_Signature_Variant::SIG_SPHINCS_SHA256_256S_ROBUST}},
        {  "SPHINCS-SHA256-256S-SIMPLE",   {Cli_Alg_Type::KEY_TYPE_PQ_SIG, Cli_PQ_Signature_Variant::SIG_SPHINCS_SHA256_256S_SIMPLE}},
        {"SPHINCS-SHAKE256-128F-ROBUST", {Cli_Alg_Type::KEY_TYPE_PQ_SIG, Cli_PQ_Signature_Variant::SIG_SPHINCS_SHAKE256_128F_ROBUST}},
        {"SPHINCS-SHAKE256-128F-SIMPLE", {Cli_Alg_Type::KEY_TYPE_PQ_SIG, Cli_PQ_Signature_Variant::SIG_SPHINCS_SHAKE256_128F_SIMPLE}},
        {"SPHINCS-SHAKE256-128S-ROBUST", {Cli_Alg_Type::KEY_TYPE_PQ_SIG, Cli_PQ_Signature_Variant::SIG_SPHINCS_SHAKE256_128S_ROBUST}},
        {"SPHINCS-SHAKE256-128S-SIMPLE", {Cli_Alg_Type::KEY_TYPE_PQ_SIG, Cli_PQ_Signature_Variant::SIG_SPHINCS_SHAKE256_128S_SIMPLE}},
        {"SPHINCS-SHAKE256-192F-ROBUST", {Cli_Alg_Type::KEY_TYPE_PQ_SIG, Cli_PQ_Signature_Variant::SIG_SPHINCS_SHAKE256_192F_ROBUST}},
        {"SPHINCS-SHAKE256-192F-SIMPLE", {Cli_Alg_Type::KEY_TYPE_PQ_SIG, Cli_PQ_Signature_Variant::SIG_SPHINCS_SHAKE256_192F_SIMPLE}},
        {"SPHINCS-SHAKE256-192S-ROBUST", {Cli_Alg_Type::KEY_TYPE_PQ_SIG, Cli_PQ_Signature_Variant::SIG_SPHINCS_SHAKE256_192S_ROBUST}},
        {"SPHINCS-SHAKE256-192S-SIMPLE", {Cli_Alg_Type::KEY_TYPE_PQ_SIG, Cli_PQ_Signature_Variant::SIG_SPHINCS_SHAKE256_192S_SIMPLE}},
        {"SPHINCS-SHAKE256-256F-ROBUST", {Cli_Alg_Type::KEY_TYPE_PQ_SIG, Cli_PQ_Signature_Variant::SIG_SPHINCS_SHAKE256_256F_ROBUST}},
        {"SPHINCS-SHAKE256-256F-SIMPLE", {Cli_Alg_Type::KEY_TYPE_PQ_SIG, Cli_PQ_Signature_Variant::SIG_SPHINCS_SHAKE256_256F_SIMPLE}},
        {"SPHINCS-SHAKE256-256S-ROBUST", {Cli_Alg_Type::KEY_TYPE_PQ_SIG, Cli_PQ_Signature_Variant::SIG_SPHINCS_SHAKE256_256S_ROBUST}},
        {"SPHINCS-SHAKE256-256S-SIMPLE", {Cli_Alg_Type::KEY_TYPE_PQ_SIG, Cli_PQ_Signature_Variant::SIG_SPHINCS_SHAKE256_256S_SIMPLE}}
    };

    KeyType parseKeyTypeAndVariantString(std::string keyTypeString)
    {
        std::transform(keyTypeString.begin(), keyTypeString.end(), keyTypeString.begin(), ::toupper);

        auto found = supportedKeyTypes.find(keyTypeString);
        if (found == supportedKeyTypes.end())
        {
            spdlog::error("Unsupported key type '{}' specified. Supported key types are", keyTypeString);
            spdlog::trace("Supported key types are:");
            for (auto &k : supportedKeyTypes)
            {
                spdlog::trace(k.first);
            }
            throw std::runtime_error("Unsupported key type");
        }

        return found->second;
    }

    bool lexical_cast(const std::string &input, KeyType &output)
    {
        output = parseKeyTypeAndVariantString(input);
        return true;
    }

    int KeyType::getVariantValue() const
    {
        int returnVal;
        std::visit([&](auto &&arg) { returnVal = static_cast<int>(arg); }, variant);

        return returnVal;
    }

} // namespace Quantinuum::QuantumOrigin::Common
