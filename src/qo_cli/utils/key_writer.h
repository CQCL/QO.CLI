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

#include <key_parameters.h>

#include <optional>
#include <ostream>
#include <string>

namespace Quantinuum::QuantumOrigin::Cli::Utils
{

    class KeyWriter
    {
      public:
        explicit KeyWriter(std::optional<KeyTypeAndVariant> keyTypeAndVariant);

        /// Function for writing the information to a file in a certain format.
        /// @param outputFormat The format the decrypted information should be written in jwk/pem/base64/hex/raw.
        /// @param contentType The type of data that is being encoded. Whether it is a RSA/AES key etc
        /// @param outputFilename Address of the file that is written to.
        void outputKeyData(const std::vector<uint8_t> &plainTextOut, Commands::OutputFormat outputFormat, std::ostream &outputStream);

      private:
        std::optional<KeyTypeAndVariant> _keyTypeAndVariant;

        /// jwk encoding of the plaintext
        /// @param pPlainTextOut is the pointer to the array of decrypted data
        /// @param cbPlainTextOut length of the array of decrypted data
        /// @param contentType what type of data this is i.e AES, RSA data
        /// @return Returns the plantext encoded in jwk
        std::string jwkEncode(const std::vector<uint8_t> &plainTextOut);

        /// pem encoding of the plaintext
        /// @param pPlainTextOut is the pointer to the array of decrypted data
        /// @param cbPlainTextOut length of the array of decrypted data
        /// @param contentType what type of data this is i.e AES, RSA data
        /// @return Returns the plantext encoded in pem
        std::string pemEncode(const std::vector<uint8_t> &plainTextOut);

        /// Function for writing the information to a file.
        /// @param outputFilename Address of the file that is written to.
        /// @param content The correctly encoded information that will be written to file.
        static void emitResult(std::ostream &outputStream, const std::string &content);
    };

} // namespace Quantinuum::QuantumOrigin::Cli::Utils
