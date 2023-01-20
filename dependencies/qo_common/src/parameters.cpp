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
#include <qo_common/exceptions.h>
#include <qo_common/parameters.h>
#include <qo_common/service.h>

#include <fmt/format.h>
#include <magic_enum.hpp>

#include <regex>
#include <string>

namespace Quantinuum::QuantumOrigin::Common
{

    template <typename T>
    EnumWrapper<T>::EnumWrapper(T t) : _t(t)
    {
    }

    template <typename T>
    EnumWrapper<T>::EnumWrapper(const char *s) : EnumWrapper(std::string(s))
    {
    }

    template <typename T>
    EnumWrapper<T>::EnumWrapper(const std::string &s)
    {
        try
        {
            // Replace hyphens with underscores then parse the string as the enum type
            _t = magic_enum::enum_cast<T>(std::regex_replace(s, std::regex("-"), "_")).value();
        }
        catch (const std::bad_optional_access &e)
        {
            throw ApiError(fmt::format("Invalid enum string '{}'", s));
        }
    }

    template <typename T>
    EnumWrapper<T>::operator T() const
    {
        return _t;
    }

    template <typename T>
    EnumWrapper<T>::operator std::string() const
    {
        // Convert the enum to a string then replace underscores with hyphens
        return std::regex_replace(std::string(magic_enum::enum_name(_t)), std::regex("_"), "-");
    }

    // Instantiate the template class with all the possible types, which allows us to keep the
    // implementation details out of the header
    template class EnumWrapper<KeyType>;
    template class EnumWrapper<EncryptionScheme>;
    template class EnumWrapper<CertType>;
    template class EnumWrapper<OaepHashFunction>;
    template class EnumWrapper<UsageQuery>;

} // namespace Quantinuum::QuantumOrigin::Common
