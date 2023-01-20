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
#include "key_file.h"

#include <cppcodec/base64_default_rfc4648.hpp>
#include <nlohmann/json.hpp>
#include <qo_decrypt/qo_cleanse.h>
#include <spdlog/spdlog.h>

#include <fstream>
#include <iostream>
#include <utility>

namespace Quantinuum::QuantumOrigin::Cli::Commands::Decrypt
{
    KeyFile::KeyFile() : _gcmCounter(0) {}

    KeyFile::KeyFile(const std::string &srcFilename) : _gcmCounter(0)
    {
        getGcmFieldsFromKeygenResponse(srcFilename);
    }

    KeyFile::~KeyFile()
    {
        Cleanse();
    }

    // Securely Cleanse
    void KeyFile::Cleanse()
    {
        SetGcmCounter(0);
        CleanseStdString(_gcmEncryptedData);
        CleanseStdString(_gcmSeed);
    }

    // Setter
    void KeyFile::SetContentType(std::string value)
    {
        _contentType = std::move(value);
    }
    // Getter
    std::string KeyFile::GetContentType()
    {
        return _contentType;
    }
    // Setter
    void KeyFile::SetGcmCounter(uint64_t value)
    {
        _gcmCounter = value;
    }
    // Getter
    uint64_t KeyFile::GetGcmCounter() const
    {
        return _gcmCounter;
    }

    // Setter
    void KeyFile::SetGcmEncryptedData(std::string value)
    {
        _gcmEncryptedData = std::move(value);
    }
    // Getter
    std::vector<uint8_t> KeyFile::GetGcmEncryptedData() const
    {
        return base64::decode(_gcmEncryptedData);
    }

    // Setter
    void KeyFile::SetGcmSeed(std::string value)
    {
        _gcmSeed = std::move(value);
    }
    // Getter
    std::vector<uint8_t> KeyFile::GetGcmSeed() const
    {
        return base64::decode(_gcmSeed);
    }

    std::string KeyFile::readContentsOfFile(const std::string &inFilename)
    {
        std::stringstream buffer;

        if (inFilename == "stdin")
        {
            spdlog::debug("Reading from stdin...");
            buffer << std::cin.rdbuf();
        }
        else
        {
            std::ifstream fInStream(inFilename, std::ios::binary);
            if (!fInStream)
            {
                throw std::runtime_error(fmt::format("Failed to open file: {}", inFilename));
            }

            buffer << fInStream.rdbuf();
        }

        std::string fileContent = buffer.str();

        spdlog::trace("Successfully read [{} bytes] from file [{}]", fileContent.size(), inFilename);
        spdlog::trace("FileContent[{}] = [{}]", fileContent.size(), fileContent);

        return fileContent;
    }

    void KeyFile::getGcmFieldsFromKeygenResponse(const std::string &srcFilename)
    {
        ////////////////////////////////////////////////////////////////////
        // nlohmann::json sample Code:
        //    auto j3 = nlohmann::json::parse(R"({"happy": true, "pi": 3.141})");  // Parse explicitly
        //    std::string s = j3.dump();                // Explicit conversion to string: {"happy":true,"pi":3.141}
        //    std::cout << s << std::endl;
        //    // Prints...
        //    // {"happy":true,"pi":3.141}
        //    std::cout << j3.dump(4) << std::endl;     // Serialization with pretty printing (indented with 4 spaces)
        //    // Prints...
        //    // {
        //    //     "happy": true,
        //    //     "pi": 3.141
        //    // }
        ////////////////////////////////////////////////////////////////////

        _contentType            = "";
        _gcmCounter             = 0;
        std::string fileContent = readContentsOfFile(srcFilename);

        auto parsedJson = nlohmann::json::parse(fileContent);

        spdlog::trace("Parsed JSON: {}", parsedJson.dump(4));

        if (parsedJson.contains("content_type"))
            _contentType = parsedJson["content_type"];
        if (parsedJson.contains("counter"))
            _gcmCounter = parsedJson["counter"];
        if (parsedJson.contains("encrypted_data"))
            _gcmEncryptedData = parsedJson["encrypted_data"];
        if (parsedJson.contains("seed"))
            _gcmSeed = parsedJson["seed"];
    }

} // namespace Quantinuum::QuantumOrigin::Cli::Commands::Decrypt
