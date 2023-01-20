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
#include "command_base.hpp"

#include <cppcodec/base64_default_rfc4648.hpp>
#include <cppcodec/hex_default_upper.hpp>
#include <fmt/format.h>
#include <spdlog/spdlog.h>

#include <filesystem>
#include <fstream>
#include <vector>

namespace Quantinuum::QuantumOrigin::Cli::Commands
{

    namespace
    {
        bool isFilename(const std::string &inString)
        {
            if (inString.length() < 2)
            {
                spdlog::trace("DEBUG: Is a filename?: NO (It is too short) [{}]", inString);
                return false;
            }
            if (inString.front() != '@') // Is this a filename
            {
                spdlog::trace("DEBUG: Is a filename?: NO (No @ prefix) [{}]", inString);
                return false;
            }

            spdlog::trace("DEBUG: Is a filename?: YES [{}]", inString);
            return true;
        }

        bool fileExists(const std::string &filename)
        {
            std::filesystem::path filePath(filename);
            return std::filesystem::exists(filePath) && std::filesystem::is_regular_file(filePath);
        }

        size_t getFilesize(const std::string &filename)
        {
            std::filesystem::path filePath(filename);
            return std::filesystem::file_size(filePath);
        }

        bool isValidInputFilename(const std::string &inString)
        {
            if (!isFilename(inString))
            {
                spdlog::trace("DEBUG: Is an input filename?: NO (It is not even a valid filename) [{}]", inString);
                return false;
            }

            // Is the remainder of the string a valid existing filename?
            std::string filename = inString.substr(1);
            if (!fileExists(filename))
            {
                spdlog::trace("DEBUG: Is an input filename?: NO (file doesn't exist) [{}]", inString);
                return false;
            }

            // And does it have content?
            size_t filesize = getFilesize(filename);
            if (filesize <= 0)
            {
                spdlog::trace("DEBUG: Is an input filename?: NO (file is empty) [{}]", inString);
                return false;
            }

            spdlog::trace("DEBUG: Is an input filename?: YES [{}]", inString);
            return true;
        }
    } // namespace

    std::string transformFilenameToValue(const std::string &inString)
    {
        std::string outString;

        // Our input string is one of these:
        //    A filename - identified by @ as the first character. The remainder of the string being the filename. The content of that file may be any of the supported
        //    types, except another filename. A json string - identified by enclosing {}, and having fields of . The content remainder of the string being the filename.
        //    The content of that file may be any of the supported types, except another filename.

        if (isFilename(inString)) // Is this a filename?
        {
            std::string inFilename = inString.substr(1);
            spdlog::trace("DEBUG: TransformFilenameToValue: Reading file [{}]", inFilename);

            if (isValidInputFilename(inString)) // Does the file exist for reading?
            {
                std::ifstream inStream(inFilename, std::ios::binary);
                std::vector<unsigned char> contentBuffer(std::istreambuf_iterator<char>(inStream), {});
                outString.append(contentBuffer.begin(), contentBuffer.end());

                spdlog::trace("DEBUG: TransformFilenameToValue [{}] to [{}]", inString, outString);
            }
            else
            {
                throw std::runtime_error(fmt::format("ERROR: Unable to read from input file (not found or empty) [{}]", inFilename));
            }
        }
        else
        {
            outString = inString;
            spdlog::trace("INFO: TransformFilenameToValue - No Transformation Needed [{}]", inString);
        }

        return outString;
    }

    const std::unordered_map<std::string, DataFormat> dataFormatMap{
        {"base64", DataFormat::Base64},
        {   "hex",    DataFormat::Hex},
        { "ascii",  DataFormat::Ascii},
        {   "raw", DataFormat::Binary},
    };

    std::string to_string(const DataFormat &x)
    {
        auto found = std::find_if(std::begin(dataFormatMap), std::end(dataFormatMap), [&](auto &&p) { return p.second == x; });

        if (found != dataFormatMap.end())
        {
            return found->first;
        }

        return "invalid format";
    }

    DataParseError::DataParseError(const std::exception &ex, DataFormat format, std::string name)
        : std::runtime_error(fmt::format("Failed parsing {} parameter in {} format: {}", name, to_string(format), ex.what()))
    {
    }

    DataParameter::DataParameter(std::string name) : name(std::move(name)) {}

    DataParameter::DataParameter(DataFormat format, std::string name) : name(std::move(name)), format(format) {}

    DataParameter::DataParameter(std::vector<uint8_t> data, std::string name) : name(std::move(name)), data(std::move(data)) {}

    DataParameter::DataParameter(std::string data, DataFormat format, std::string name) : name(std::move(name)), dataString(std::move(data)), format(format) {}

    DataFormat &DataParameter::getFormat()
    {
        return format;
    }

    std::string &DataParameter::getDataString()
    {
        return dataString;
    }

    void DataParameter::parse()
    {
        if (dataString.empty())
        {
            data = std::vector<uint8_t>{};
        }

        try
        {
            switch (format)
            {
                case DataFormat::Base64:
                    data = base64::decode(dataString);
                    break;
                case DataFormat::Hex:
                    data = hex::decode(dataString);
                    break;
                case DataFormat::Ascii:
                case DataFormat::Binary:
                    data = std::vector<uint8_t>(dataString.begin(), dataString.end());
                    break;
                default:
                    throw std::runtime_error("Unexpected data format");
            }
        }
        catch (const std::exception &ex)
        {
            throw DataParseError(ex, format, name);
        }
    }

    const std::vector<uint8_t> &DataParameter::getData()
    {
        if (!data)
        {
            parse();
        }

        return *data;
    }

    MissingParameterError::MissingParameterError(const std::string &parameterName)
        : std::runtime_error(fmt::format("{} parameter is required but was not supplied", parameterName))
    {
    }

} // namespace Quantinuum::QuantumOrigin::Cli::Commands
