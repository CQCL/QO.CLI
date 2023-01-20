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

#include <string>
#include <vector>

namespace Quantinuum::QuantumOrigin::Cli::Commands::Decrypt
{

    class KeyFile
    {
      private:
        std::string _contentType;
        uint64_t _gcmCounter;
        std::string _gcmEncryptedData;
        std::string _gcmSeed;

      public:
        KeyFile();
        explicit KeyFile(const std::string &srcFilename);
        ~KeyFile();

        void SetContentType(std::string value);
        std::string GetContentType();
        void SetGcmCounter(uint64_t value);
        [[nodiscard]] uint64_t GetGcmCounter() const;
        void SetGcmEncryptedData(std::string value);
        [[nodiscard]] std::vector<uint8_t> GetGcmEncryptedData() const;
        void SetGcmSeed(std::string value);
        [[nodiscard]] std::vector<uint8_t> GetGcmSeed() const;

        void getGcmFieldsFromKeygenResponse(const std::string &srcFilename);

      private:
        static std::string readContentsOfFile(const std::string &inFilename);

        void Cleanse();
    };

} // namespace Quantinuum::QuantumOrigin::Cli::Commands::Decrypt
