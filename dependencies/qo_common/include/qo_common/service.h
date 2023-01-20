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

#include "key_request.h"
#include "key_response.h"
#include "onboard_request.h"
#include "onboard_response.h"
#include "parameters.h"

#include <curl/curl.h>

#include <array>
#include <exception>
#include <mutex>
#include <optional>

namespace Quantinuum::QuantumOrigin::Common
{

    enum class CertType
    {
        PEM,
        DER,
        P12,
    };

    using CertTypeEnum = EnumWrapper<CertType>;

    class Connection
    {
      public:
        /// Constructor that sets up the connection with the Quantum Origin API. Takes in variables for the authentication
        /// @param baseUrl The url of the server the user wishes to hit. Will be appended with the keygen endpoint.
        /// @param certificate The file location of the customer certificate. Should be registered with Quantum Origin.
        /// @param certType The type of certificate that will be used.
        /// @param privateKeyForCert The file location of the private key the matches the certificate.
        /// @param inMemory Whether the certificate and key are in-memory blobs rather than filenames.
        /// @throws ApiError If initialisation fails
        Connection(std::string baseUrl, std::string certificate, CertTypeEnum certType, std::string privateKeyForCert, bool inMemory = false);

        /// Constructor that sets up the connection with the Quantum Origin API. Takes in variables for the authentication
        /// @param baseUrl The url of the server the user wishes to hit. Will be appended with the keygen endpoint.
        /// @param certificate The file location of the customer certificate. Should be registered with Quantum Origin.
        /// @param certType The type of certificate that will be used.
        /// @param privateKeyForCert The file location of the private key the matches the certificate.
        /// @param apiKey Additional API key to be placed in a header of the request.
        /// @param inMemory Whether the certificate and key are in-memory blobs rather than filenames.
        /// @throws ApiError If initialisation fails
        Connection(
            std::string baseUrl, std::string certificate, CertTypeEnum certType, std::string privateKeyForCert, std::optional<std::string> apiKey, bool inMemory = false);

        /// Constructor that sets up the connection with the Quantum Origin API. Takes in variables for the authentication
        /// @param baseUrl The url of the server the user wishes to hit. Will be appended with the keygen endpoint.
        /// @param clientId Client ID to be placed in a header of the request.
        /// @param apiKey Additional API key to be placed in a header of the request.
        /// @throws ApiError If initialisation fails
        Connection(std::string baseUrl, std::string clientId, std::optional<std::string> apiKey = std::nullopt);

        // Constructor that sets up the connection with Quantum Origin API without certificate information, for onboarding purposes.
        /// @param baseUrl The url of the server the user wishes to hit. Will be appended with the keygen endpoint.
        /// @throws ApiError If initialisation fails
        explicit Connection(std::string baseUrl);

        /// Destructor that also cleans up the curl information used for the connection.
        ~Connection();

        // Implement move operations
        Connection(Connection &&other) noexcept;
        Connection &operator=(Connection &&other) noexcept;

        /// @brief Send a curl request using any set up authentication credentials. The curl's body is a json output of the Request.
        ///
        /// The `curl_easy_perform` function we use should not be used with the same handle from multiple threads at the same time,
        /// so this function is not thread-safe, and one instance of this class should also not be used from multiple threads at the same time.
        /// If you want to make requests from multiple threads, you should instantiate a separate `Connection` for each thread.
        ///
        /// @param keyRequest A class that is used to generate the curl's body in JSON.
        /// @return The response parsed from the response data
        /// @throws HttpErrorCode If the service returns a non-2xx status code
        /// @throws ApiError If any other errors occur
        template <typename R>
        typename R::Response send(const R &request)
        {
            return typename R::Response(sendImpl(request));
        }

        /// @brief Add headers that will be included in the curl request
        ///
        /// @param header A string containing a complete header (e.g. 'qo-api-key: <key>')
        void addHeader(const std::string &header);

        /// @brief Configure Curl to use a web proxy server
        ///
        /// @param proxy URL of the proxy server
        void setProxy(const std::string &proxy);

        /// @brief Set the timeout for transfer operations
        ///
        /// @param timeout Timeout length in seconds
        void setTimeout(long timeout);

        /// @brief Set the timeout for connect operations
        ///
        /// @param timeout Timeout length in seconds
        void setConnectTimeout(long timeout);

        /// @brief Enables or disables the use of OS-native CA store (only has any effect on Windows)
        ///
        /// @param enabled Whether to enable or disable
        void setNativeCa(bool enabled);

        /// @brief Sets the filepath of the CA certificate bundle used to verify host certificates.
        ///
        /// @param filename Certificate bundle filename
        void setCaBundleFile(const std::string &filename);

      private:
        void initializeLibCurl();
        /// Prepares the curl request using the authentication credentials provided in the constructor.
        void setUpConnection();

        std::vector<std::string> sendImpl(const Request &request);

        template <typename T>
        void setCurlOption(CURLoption option, T parameter);

        void runCurl();

        CURL *hCurl;
        struct curl_slist *curlHeaders = nullptr;

        std::string _baseUrl;

        // Certificate
        std::optional<std::string> _certificate;
        std::optional<std::string> _certType;
        std::optional<std::string> _privateKeyForCert;
        std::array<char, CURL_ERROR_SIZE> _curlErrorBuffer = {0};
        std::vector<std::string> _headers                  = {};
        bool _inMemory                                     = false;
        bool _clientIdProvided                             = false;

        // Static mutex to provide locking around non-threadsafe global initialisation
        static std::mutex _initMutex;
    };

} // namespace Quantinuum::QuantumOrigin::Common
