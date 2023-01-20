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
#include "key_parameters.h"

#include <spdlog/spdlog.h>

#include <stdexcept>

namespace Quantinuum::QuantumOrigin::Cli
{

    const std::unordered_map<std::string, KeyTypeAndVariant> supportedKeyTypes = {
        {                        "RAND",                                                                 {CliLocal_Key_Type::KEY_TYPE_RAND, 0}},
        {                     "AES-128",                                      {CliLocal_Key_Type::KEY_TYPE_AES, CliLocal_AES_Variant::AES_128}},
        {                     "AES-192",                                      {CliLocal_Key_Type::KEY_TYPE_AES, CliLocal_AES_Variant::AES_192}},
        {                     "AES-256",                                      {CliLocal_Key_Type::KEY_TYPE_AES, CliLocal_AES_Variant::AES_256}},

        {                    "RSA-2048",                                     {CliLocal_Key_Type::KEY_TYPE_RSA, CliLocal_RSA_Variant::RSA_2048}},
        {                    "RSA-3072",                                     {CliLocal_Key_Type::KEY_TYPE_RSA, CliLocal_RSA_Variant::RSA_3072}},
        {                    "RSA-4096",                                     {CliLocal_Key_Type::KEY_TYPE_RSA, CliLocal_RSA_Variant::RSA_4096}},

        {                  "EC-BP256R1",                                        {CliLocal_Key_Type::KEY_TYPE_EC, CliLocal_EC_Variant::BP256R1}},
        {                  "EC-BP384R1",                                        {CliLocal_Key_Type::KEY_TYPE_EC, CliLocal_EC_Variant::BP384R1}},
        {                  "EC-BP512R1",                                        {CliLocal_Key_Type::KEY_TYPE_EC, CliLocal_EC_Variant::BP512R1}},
        {                "EC-SECP192K1",                                      {CliLocal_Key_Type::KEY_TYPE_EC, CliLocal_EC_Variant::SECP192K1}},
        {                "EC-SECP192R1",                                      {CliLocal_Key_Type::KEY_TYPE_EC, CliLocal_EC_Variant::SECP192R1}},
        {                "EC-SECP224K1",                                      {CliLocal_Key_Type::KEY_TYPE_EC, CliLocal_EC_Variant::SECP224K1}},
        {                "EC-SECP224R1",                                      {CliLocal_Key_Type::KEY_TYPE_EC, CliLocal_EC_Variant::SECP224R1}},
        {                "EC-SECP256K1",                                      {CliLocal_Key_Type::KEY_TYPE_EC, CliLocal_EC_Variant::SECP256K1}},
        {                "EC-SECP256R1",                                      {CliLocal_Key_Type::KEY_TYPE_EC, CliLocal_EC_Variant::SECP256R1}},
        {                "EC-SECP384R1",                                      {CliLocal_Key_Type::KEY_TYPE_EC, CliLocal_EC_Variant::SECP384R1}},
        {                "EC-SECP521R1",                                      {CliLocal_Key_Type::KEY_TYPE_EC, CliLocal_EC_Variant::SECP521R1}},
        {                   "EC-X25519",                                         {CliLocal_Key_Type::KEY_TYPE_EC, CliLocal_EC_Variant::X25519}},

        {                       "SABER",                              {CliLocal_Key_Type::KEY_TYPE_PQ_KEM, CliLocal_PQ_KEM_Variant::KEM_SABER}},
        {                   "FIRESABER",                          {CliLocal_Key_Type::KEY_TYPE_PQ_KEM, CliLocal_PQ_KEM_Variant::KEM_FIRESABER}},
        {                  "LIGHTSABER",                         {CliLocal_Key_Type::KEY_TYPE_PQ_KEM, CliLocal_PQ_KEM_Variant::KEM_LIGHTSABER}},
        {     "CLASSIC-MCELIECE-348864",                    {CliLocal_Key_Type::KEY_TYPE_PQ_KEM, CliLocal_PQ_KEM_Variant::KEM_MCELIECE_348864}},
        {    "CLASSIC-MCELIECE-348864F",                   {CliLocal_Key_Type::KEY_TYPE_PQ_KEM, CliLocal_PQ_KEM_Variant::KEM_MCELIECE_348864F}},
        {     "CLASSIC-MCELIECE-460896",                    {CliLocal_Key_Type::KEY_TYPE_PQ_KEM, CliLocal_PQ_KEM_Variant::KEM_MCELIECE_460896}},
        {    "CLASSIC-MCELIECE-460896F",                   {CliLocal_Key_Type::KEY_TYPE_PQ_KEM, CliLocal_PQ_KEM_Variant::KEM_MCELIECE_460896F}},
        {    "CLASSIC-MCELIECE-6688128",                   {CliLocal_Key_Type::KEY_TYPE_PQ_KEM, CliLocal_PQ_KEM_Variant::KEM_MCELIECE_6688128}},
        {   "CLASSIC-MCELIECE-6688128F",                  {CliLocal_Key_Type::KEY_TYPE_PQ_KEM, CliLocal_PQ_KEM_Variant::KEM_MCELIECE_6688128F}},
        {    "CLASSIC-MCELIECE-6960119",                   {CliLocal_Key_Type::KEY_TYPE_PQ_KEM, CliLocal_PQ_KEM_Variant::KEM_MCELIECE_6960119}},
        {   "CLASSIC-MCELIECE-6960119F",                  {CliLocal_Key_Type::KEY_TYPE_PQ_KEM, CliLocal_PQ_KEM_Variant::KEM_MCELIECE_6960119F}},
        {    "CLASSIC-MCELIECE-8192128",                   {CliLocal_Key_Type::KEY_TYPE_PQ_KEM, CliLocal_PQ_KEM_Variant::KEM_MCELIECE_8192128}},
        {   "CLASSIC-MCELIECE-8192128F",                  {CliLocal_Key_Type::KEY_TYPE_PQ_KEM, CliLocal_PQ_KEM_Variant::KEM_MCELIECE_8192128F}},
        {                    "KYBER512",                          {CliLocal_Key_Type::KEY_TYPE_PQ_KEM, CliLocal_PQ_KEM_Variant::KEM_KYBER_512}},
        {                "KYBER512-90S",                      {CliLocal_Key_Type::KEY_TYPE_PQ_KEM, CliLocal_PQ_KEM_Variant::KEM_KYBER_512_90S}},
        {                   "KYBER1024",                         {CliLocal_Key_Type::KEY_TYPE_PQ_KEM, CliLocal_PQ_KEM_Variant::KEM_KYBER_1024}},
        {               "KYBER1024-90S",                     {CliLocal_Key_Type::KEY_TYPE_PQ_KEM, CliLocal_PQ_KEM_Variant::KEM_KYBER_1024_90S}},
        {                    "KYBER768",                          {CliLocal_Key_Type::KEY_TYPE_PQ_KEM, CliLocal_PQ_KEM_Variant::KEM_KYBER_768}},
        {                "KYBER768-90S",                      {CliLocal_Key_Type::KEY_TYPE_PQ_KEM, CliLocal_PQ_KEM_Variant::KEM_KYBER_768_90S}},
        {               "NTRU-2048-509",                      {CliLocal_Key_Type::KEY_TYPE_PQ_KEM, CliLocal_PQ_KEM_Variant::KEM_NTRU_2048_509}},
        {               "NTRU-2048-677",                      {CliLocal_Key_Type::KEY_TYPE_PQ_KEM, CliLocal_PQ_KEM_Variant::KEM_NTRU_2048_677}},
        {               "NTRU-4096-821",                      {CliLocal_Key_Type::KEY_TYPE_PQ_KEM, CliLocal_PQ_KEM_Variant::KEM_NTRU_4096_821}},
        {               "NTRU-HRSS-701",                      {CliLocal_Key_Type::KEY_TYPE_PQ_KEM, CliLocal_PQ_KEM_Variant::KEM_NTRU_HRSS_701}},
        {                 "NTRULPR-653",                        {CliLocal_Key_Type::KEY_TYPE_PQ_KEM, CliLocal_PQ_KEM_Variant::KEM_NTRULPR_653}},
        {                 "NTRULPR-761",                        {CliLocal_Key_Type::KEY_TYPE_PQ_KEM, CliLocal_PQ_KEM_Variant::KEM_NTRULPR_761}},
        {                 "NTRULPR-857",                        {CliLocal_Key_Type::KEY_TYPE_PQ_KEM, CliLocal_PQ_KEM_Variant::KEM_NTRULPR_857}},
        {                "NTRULPR-1277",                       {CliLocal_Key_Type::KEY_TYPE_PQ_KEM, CliLocal_PQ_KEM_Variant::KEM_NTRULPR_1277}},
        {                  "SNTRUP-653",                         {CliLocal_Key_Type::KEY_TYPE_PQ_KEM, CliLocal_PQ_KEM_Variant::KEM_SNTRUP_653}},
        {                  "SNTRUP-761",                         {CliLocal_Key_Type::KEY_TYPE_PQ_KEM, CliLocal_PQ_KEM_Variant::KEM_SNTRUP_761}},
        {                  "SNTRUP-857",                         {CliLocal_Key_Type::KEY_TYPE_PQ_KEM, CliLocal_PQ_KEM_Variant::KEM_SNTRUP_857}},
        {                 "SNTRUP-1277",                        {CliLocal_Key_Type::KEY_TYPE_PQ_KEM, CliLocal_PQ_KEM_Variant::KEM_SNTRUP_1277}},
        {                     "HQC-128",                            {CliLocal_Key_Type::KEY_TYPE_PQ_KEM, CliLocal_PQ_KEM_Variant::KEM_HQC_128}},
        {                     "HQC-192",                            {CliLocal_Key_Type::KEY_TYPE_PQ_KEM, CliLocal_PQ_KEM_Variant::KEM_HQC_192}},
        {                     "HQC-256",                            {CliLocal_Key_Type::KEY_TYPE_PQ_KEM, CliLocal_PQ_KEM_Variant::KEM_HQC_256}},
        {                     "BIKE-L1",                            {CliLocal_Key_Type::KEY_TYPE_PQ_KEM, CliLocal_PQ_KEM_Variant::KEM_BIKE_L1}},
        {                     "BIKE-L3",                            {CliLocal_Key_Type::KEY_TYPE_PQ_KEM, CliLocal_PQ_KEM_Variant::KEM_BIKE_L3}},

        {                  "DILITHIUM2",                   {CliLocal_Key_Type::KEY_TYPE_PQ_SIG, CliLocal_PQ_Signature_Variant::SIG_DILITHIUM2}},
        {                  "DILITHIUM3",                   {CliLocal_Key_Type::KEY_TYPE_PQ_SIG, CliLocal_PQ_Signature_Variant::SIG_DILITHIUM3}},
        {                  "DILITHIUM5",                   {CliLocal_Key_Type::KEY_TYPE_PQ_SIG, CliLocal_PQ_Signature_Variant::SIG_DILITHIUM5}},
        {              "DILITHIUM2-AES",               {CliLocal_Key_Type::KEY_TYPE_PQ_SIG, CliLocal_PQ_Signature_Variant::SIG_DILITHIUM2_AES}},
        {              "DILITHIUM3-AES",               {CliLocal_Key_Type::KEY_TYPE_PQ_SIG, CliLocal_PQ_Signature_Variant::SIG_DILITHIUM3_AES}},
        {              "DILITHIUM5-AES",               {CliLocal_Key_Type::KEY_TYPE_PQ_SIG, CliLocal_PQ_Signature_Variant::SIG_DILITHIUM5_AES}},
        {           "RAINBOW-I-CLASSIC",            {CliLocal_Key_Type::KEY_TYPE_PQ_SIG, CliLocal_PQ_Signature_Variant::SIG_RAINBOW_I_CLASSIC}},
        {    "RAINBOW-I-CIRCUMZENITHAL",     {CliLocal_Key_Type::KEY_TYPE_PQ_SIG, CliLocal_PQ_Signature_Variant::SIG_RAINBOW_I_CIRCUMZENITHAL}},
        {        "RAINBOW-I-COMPRESSED",         {CliLocal_Key_Type::KEY_TYPE_PQ_SIG, CliLocal_PQ_Signature_Variant::SIG_RAINBOW_I_COMPRESSED}},
        {         "RAINBOW-III-CLASSIC",          {CliLocal_Key_Type::KEY_TYPE_PQ_SIG, CliLocal_PQ_Signature_Variant::SIG_RAINBOW_III_CLASSIC}},
        {  "RAINBOW-III-CIRCUMZENITHAL",   {CliLocal_Key_Type::KEY_TYPE_PQ_SIG, CliLocal_PQ_Signature_Variant::SIG_RAINBOW_III_CIRCUMZENITHAL}},
        {      "RAINBOW-III-COMPRESSED",       {CliLocal_Key_Type::KEY_TYPE_PQ_SIG, CliLocal_PQ_Signature_Variant::SIG_RAINBOW_III_COMPRESSED}},
        {           "RAINBOW-V-CLASSIC",            {CliLocal_Key_Type::KEY_TYPE_PQ_SIG, CliLocal_PQ_Signature_Variant::SIG_RAINBOW_V_CLASSIC}},
        {    "RAINBOW-V-CIRCUMZENITHAL",     {CliLocal_Key_Type::KEY_TYPE_PQ_SIG, CliLocal_PQ_Signature_Variant::SIG_RAINBOW_V_CIRCUMZENITHAL}},
        {        "RAINBOW-V-COMPRESSED",         {CliLocal_Key_Type::KEY_TYPE_PQ_SIG, CliLocal_PQ_Signature_Variant::SIG_RAINBOW_V_COMPRESSED}},
        {                  "FALCON-512",                   {CliLocal_Key_Type::KEY_TYPE_PQ_SIG, CliLocal_PQ_Signature_Variant::SIG_FALCON_512}},
        {                 "FALCON-1024",                  {CliLocal_Key_Type::KEY_TYPE_PQ_SIG, CliLocal_PQ_Signature_Variant::SIG_FALCON_1024}},
        {  "SPHINCS-HARAKA-128F-ROBUST",   {CliLocal_Key_Type::KEY_TYPE_PQ_SIG, CliLocal_PQ_Signature_Variant::SIG_SPHINCS_HARAKA_128F_ROBUST}},
        {  "SPHINCS-HARAKA-128F-SIMPLE",   {CliLocal_Key_Type::KEY_TYPE_PQ_SIG, CliLocal_PQ_Signature_Variant::SIG_SPHINCS_HARAKA_128F_SIMPLE}},
        {  "SPHINCS-HARAKA-128S-ROBUST",   {CliLocal_Key_Type::KEY_TYPE_PQ_SIG, CliLocal_PQ_Signature_Variant::SIG_SPHINCS_HARAKA_128S_ROBUST}},
        {  "SPHINCS-HARAKA-128S-SIMPLE",   {CliLocal_Key_Type::KEY_TYPE_PQ_SIG, CliLocal_PQ_Signature_Variant::SIG_SPHINCS_HARAKA_128S_SIMPLE}},
        {  "SPHINCS-HARAKA-192F-ROBUST",   {CliLocal_Key_Type::KEY_TYPE_PQ_SIG, CliLocal_PQ_Signature_Variant::SIG_SPHINCS_HARAKA_192F_ROBUST}},
        {  "SPHINCS-HARAKA-192F-SIMPLE",   {CliLocal_Key_Type::KEY_TYPE_PQ_SIG, CliLocal_PQ_Signature_Variant::SIG_SPHINCS_HARAKA_192F_SIMPLE}},
        {  "SPHINCS-HARAKA-192S-ROBUST",   {CliLocal_Key_Type::KEY_TYPE_PQ_SIG, CliLocal_PQ_Signature_Variant::SIG_SPHINCS_HARAKA_192S_ROBUST}},
        {  "SPHINCS-HARAKA-192S-SIMPLE",   {CliLocal_Key_Type::KEY_TYPE_PQ_SIG, CliLocal_PQ_Signature_Variant::SIG_SPHINCS_HARAKA_192S_SIMPLE}},
        {  "SPHINCS-HARAKA-256F-ROBUST",   {CliLocal_Key_Type::KEY_TYPE_PQ_SIG, CliLocal_PQ_Signature_Variant::SIG_SPHINCS_HARAKA_256F_ROBUST}},
        {  "SPHINCS-HARAKA-256F-SIMPLE",   {CliLocal_Key_Type::KEY_TYPE_PQ_SIG, CliLocal_PQ_Signature_Variant::SIG_SPHINCS_HARAKA_256F_SIMPLE}},
        {  "SPHINCS-HARAKA-256S-ROBUST",   {CliLocal_Key_Type::KEY_TYPE_PQ_SIG, CliLocal_PQ_Signature_Variant::SIG_SPHINCS_HARAKA_256S_ROBUST}},
        {  "SPHINCS-HARAKA-256S-SIMPLE",   {CliLocal_Key_Type::KEY_TYPE_PQ_SIG, CliLocal_PQ_Signature_Variant::SIG_SPHINCS_HARAKA_256S_SIMPLE}},
        {  "SPHINCS-SHA256-128F-ROBUST",   {CliLocal_Key_Type::KEY_TYPE_PQ_SIG, CliLocal_PQ_Signature_Variant::SIG_SPHINCS_SHA256_128F_ROBUST}},
        {  "SPHINCS-SHA256-128F-SIMPLE",   {CliLocal_Key_Type::KEY_TYPE_PQ_SIG, CliLocal_PQ_Signature_Variant::SIG_SPHINCS_SHA256_128F_SIMPLE}},
        {  "SPHINCS-SHA256-128S-ROBUST",   {CliLocal_Key_Type::KEY_TYPE_PQ_SIG, CliLocal_PQ_Signature_Variant::SIG_SPHINCS_SHA256_128S_ROBUST}},
        {  "SPHINCS-SHA256-128S-SIMPLE",   {CliLocal_Key_Type::KEY_TYPE_PQ_SIG, CliLocal_PQ_Signature_Variant::SIG_SPHINCS_SHA256_128S_SIMPLE}},
        {  "SPHINCS-SHA256-192F-ROBUST",   {CliLocal_Key_Type::KEY_TYPE_PQ_SIG, CliLocal_PQ_Signature_Variant::SIG_SPHINCS_SHA256_192F_ROBUST}},
        {  "SPHINCS-SHA256-192F-SIMPLE",   {CliLocal_Key_Type::KEY_TYPE_PQ_SIG, CliLocal_PQ_Signature_Variant::SIG_SPHINCS_SHA256_192F_SIMPLE}},
        {  "SPHINCS-SHA256-192S-ROBUST",   {CliLocal_Key_Type::KEY_TYPE_PQ_SIG, CliLocal_PQ_Signature_Variant::SIG_SPHINCS_SHA256_192S_ROBUST}},
        {  "SPHINCS-SHA256-192S-SIMPLE",   {CliLocal_Key_Type::KEY_TYPE_PQ_SIG, CliLocal_PQ_Signature_Variant::SIG_SPHINCS_SHA256_192S_SIMPLE}},
        {  "SPHINCS-SHA256-256F-ROBUST",   {CliLocal_Key_Type::KEY_TYPE_PQ_SIG, CliLocal_PQ_Signature_Variant::SIG_SPHINCS_SHA256_256F_ROBUST}},
        {  "SPHINCS-SHA256-256F-SIMPLE",   {CliLocal_Key_Type::KEY_TYPE_PQ_SIG, CliLocal_PQ_Signature_Variant::SIG_SPHINCS_SHA256_256F_SIMPLE}},
        {  "SPHINCS-SHA256-256S-ROBUST",   {CliLocal_Key_Type::KEY_TYPE_PQ_SIG, CliLocal_PQ_Signature_Variant::SIG_SPHINCS_SHA256_256S_ROBUST}},
        {  "SPHINCS-SHA256-256S-SIMPLE",   {CliLocal_Key_Type::KEY_TYPE_PQ_SIG, CliLocal_PQ_Signature_Variant::SIG_SPHINCS_SHA256_256S_SIMPLE}},
        {"SPHINCS-SHAKE256-128F-ROBUST", {CliLocal_Key_Type::KEY_TYPE_PQ_SIG, CliLocal_PQ_Signature_Variant::SIG_SPHINCS_SHAKE256_128F_ROBUST}},
        {"SPHINCS-SHAKE256-128F-SIMPLE", {CliLocal_Key_Type::KEY_TYPE_PQ_SIG, CliLocal_PQ_Signature_Variant::SIG_SPHINCS_SHAKE256_128F_SIMPLE}},
        {"SPHINCS-SHAKE256-128S-ROBUST", {CliLocal_Key_Type::KEY_TYPE_PQ_SIG, CliLocal_PQ_Signature_Variant::SIG_SPHINCS_SHAKE256_128S_ROBUST}},
        {"SPHINCS-SHAKE256-128S-SIMPLE", {CliLocal_Key_Type::KEY_TYPE_PQ_SIG, CliLocal_PQ_Signature_Variant::SIG_SPHINCS_SHAKE256_128S_SIMPLE}},
        {"SPHINCS-SHAKE256-192F-ROBUST", {CliLocal_Key_Type::KEY_TYPE_PQ_SIG, CliLocal_PQ_Signature_Variant::SIG_SPHINCS_SHAKE256_192F_ROBUST}},
        {"SPHINCS-SHAKE256-192F-SIMPLE", {CliLocal_Key_Type::KEY_TYPE_PQ_SIG, CliLocal_PQ_Signature_Variant::SIG_SPHINCS_SHAKE256_192F_SIMPLE}},
        {"SPHINCS-SHAKE256-192S-ROBUST", {CliLocal_Key_Type::KEY_TYPE_PQ_SIG, CliLocal_PQ_Signature_Variant::SIG_SPHINCS_SHAKE256_192S_ROBUST}},
        {"SPHINCS-SHAKE256-192S-SIMPLE", {CliLocal_Key_Type::KEY_TYPE_PQ_SIG, CliLocal_PQ_Signature_Variant::SIG_SPHINCS_SHAKE256_192S_SIMPLE}},
        {"SPHINCS-SHAKE256-256F-ROBUST", {CliLocal_Key_Type::KEY_TYPE_PQ_SIG, CliLocal_PQ_Signature_Variant::SIG_SPHINCS_SHAKE256_256F_ROBUST}},
        {"SPHINCS-SHAKE256-256F-SIMPLE", {CliLocal_Key_Type::KEY_TYPE_PQ_SIG, CliLocal_PQ_Signature_Variant::SIG_SPHINCS_SHAKE256_256F_SIMPLE}},
        {"SPHINCS-SHAKE256-256S-ROBUST", {CliLocal_Key_Type::KEY_TYPE_PQ_SIG, CliLocal_PQ_Signature_Variant::SIG_SPHINCS_SHAKE256_256S_ROBUST}},
        {"SPHINCS-SHAKE256-256S-SIMPLE", {CliLocal_Key_Type::KEY_TYPE_PQ_SIG, CliLocal_PQ_Signature_Variant::SIG_SPHINCS_SHAKE256_256S_SIMPLE}}
    };

    KeyTypeAndVariant parseKeyTypeAndVariantString(std::string keyTypeString)
    {
        transform(keyTypeString.begin(), keyTypeString.end(), keyTypeString.begin(), ::toupper);

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

    bool lexical_cast(const std::string &input, KeyTypeAndVariant &output)
    {
        output = parseKeyTypeAndVariantString(input);
        return true;
    }

    Commands::OutputFormat defaultOutputFormat(const std::optional<KeyTypeAndVariant> &keyTypeAndVariant)
    {
        if (keyTypeAndVariant)
        {
            if (keyTypeAndVariant->keyType == CliLocal_Key_Type::KEY_TYPE_RSA || keyTypeAndVariant->keyType == CliLocal_Key_Type::KEY_TYPE_EC)
            {
                return Cli::Commands::OutputFormat::Pem;
            }
            else if (keyTypeAndVariant->keyType == CliLocal_Key_Type::KEY_TYPE_AES || keyTypeAndVariant->keyType == CliLocal_Key_Type::KEY_TYPE_RAND)
            {
                return Cli::Commands::OutputFormat::Base64;
            }
        }

        return Cli::Commands::OutputFormat::Jwk;
    }

} // namespace Quantinuum::QuantumOrigin::Cli
