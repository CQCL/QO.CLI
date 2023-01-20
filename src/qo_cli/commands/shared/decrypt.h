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

#include "key_parameters.h"
#include "parameter_base.h"

#include "qo_common/key_response.h"
#include "spdlog/spdlog.h"

#include <optional>
#include <ostream>
#include <string>
#include <vector>

#define PAYLOAD_DATA_MINIMUM_LEN (16) // AES128 is currently the smallest key request that we support
#define PAYLOAD_TAG_LEN          (16)

namespace Quantinuum::QuantumOrigin::Cli::Commands
{

    /// This class handles the decryption of data received from the QO API.

    class CliDecrypt
    {
      private:
        // Data
        std::vector<uint8_t> _nonce;
        std::vector<uint8_t> _sharedSecret;
        std::vector<uint8_t> _seed;
        uint64_t _counter;
        std::vector<uint8_t> _encryptedData;
        std::optional<KeyTypeAndVariant> _keyTypeAndVariant;

        // Decrypted result
        std::vector<uint8_t> _pPlainTextOut;

      public:
        /// Generate the class using the parsed response of the API as output by QO-Common
        /// @param sharedSecret The shared secret that should be used to decrypt the data in raw format
        /// @param nonce The nonce that should be used to decrypt the data in raw format
        /// @param keyResponse The QO-Common response from a key quest after parsing the raw content.
        CliDecrypt(const std::vector<uint8_t> &sharedSecret, const std::vector<uint8_t> &nonce, const Quantinuum::QuantumOrigin::Common::KeyResponse &keyResponse);

        /// @param sharedSecret The shared secret that should be used to decrypt the data in raw format
        /// @param nonce The nonce that should be used to decrypt the data in raw format
        /// @param seed The seed as returned by the API.
        /// @param counter The counter as returned by the API.
        /// @param encryptedData The encrypted data as returned by the API.
        /// @param keyTypeAndVariant The type of key/data that is being decrypted.
        CliDecrypt(
            const std::vector<uint8_t> &sharedSecret, const std::vector<uint8_t> &nonce, std::vector<uint8_t> seed, uint64_t counter, std::vector<uint8_t> encryptedData,
            std::optional<KeyTypeAndVariant> keyTypeAndVariant = std::nullopt);

        /// A custom destructor is defined to provide Zeroisation for shared secret and any decrypted text
        ~CliDecrypt();

        /// Sets up the plain text. If the ciphertext is of incorrect size will throw. Setup down here to allow destructor to clear any sensitive cryptographic data.
        void init();

        /// Decrypts the ciphertext and writes the result to _pPlainTextOut
        void decryptAesGcm();

        /// Function for writing the information to a file in a certain format.
        /// @param outputFormat The format the decrypted information should be written in jwk/pem/base64/hex/raw.
        /// @param contentType The type of data that is being encoded. Whether it is a RSA/AES key etc
        /// @param outputFilename Address of the file that is written to.
        void output(Quantinuum::QuantumOrigin::Cli::Commands::OutputFormat outputFormat, std::ostream &outputStream);

        void runDecrypt(std::optional<Quantinuum::QuantumOrigin::Cli::Commands::OutputFormat> outputFormat, std::ostream &outputStream);

        const std::vector<uint8_t> &getResult() const;

      private:
        /// jwk encoding of the plaintext
        /// @param pPlainTextOut is the pointer to the array of decrypted data
        /// @param cbPlainTextOut length of the array of decrypted data
        /// @param contentType what type of data this is i.e AES, RSA data
        /// @return Returns the plantext encoded in jwk
        std::string jwkEncode(const uint8_t *pPlainTextOut, const size_t &cbPlainTextOut);

        /// pem encoding of the plaintext
        /// @param pPlainTextOut is the pointer to the array of decrypted data
        /// @param cbPlainTextOut length of the array of decrypted data
        /// @param contentType what type of data this is i.e AES, RSA data
        /// @return Returns the plantext encoded in pem
        std::string pemEncode(const uint8_t *pPlainTextOut, size_t cbPlainTextOut);

        /// Function for writing the information to a file.
        /// @param outputFilename Address of the file that is written to.
        /// @param content The correctly encoded information that will be written to file.
        static void emitResult(std::ostream &outputStream, const std::string &content);
    };

} // namespace Quantinuum::QuantumOrigin::Cli::Commands
