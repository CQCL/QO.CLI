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
#include <qo_common/service.h>

#include "qo_common/request.h"
#include "spdlog/spdlog.h"

#include <vector>
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#else
#include <unistd.h>
#endif

namespace Quantinuum::QuantumOrigin::Common
{

    class CurlError : public ApiError
    {
      public:
        CurlError(CURLcode rv, const std::string &curlErrorBuffer) : ApiError(fmt::format("Curl error {} performing request: {}", rv, curlErrorBuffer)) {}
    };

    std::mutex Connection::_initMutex;

    Connection::Connection(std::string baseUrl, std::string certificate, CertTypeEnum certType, std::string privateKeyForCert, bool inMemory)
        : Connection(std::move(baseUrl), std::move(certificate), certType, std::move(privateKeyForCert), std::nullopt, inMemory)
    {
    }

    Connection::Connection(
        std::string baseUrl, std::string certificate, CertTypeEnum certType, std::string privateKeyForCert, std::optional<std::string> apiKey, bool inMemory)
        : hCurl(nullptr), _baseUrl(std::move(baseUrl)), _certificate(std::move(certificate)), _certType(certType), _privateKeyForCert(std::move(privateKeyForCert)),
          _inMemory(inMemory)
    {
        if (apiKey)
        {
            addHeader(fmt::format("qo-api-key: {}", *apiKey));
        }
        initializeLibCurl();
    }

    Connection::Connection(std::string baseUrl, std::string clientId, std::optional<std::string> apiKey) : hCurl(nullptr), _baseUrl(std::move(baseUrl))
    {
        if (apiKey)
        {
            addHeader(fmt::format("qo-api-key: {}", *apiKey));
        }
        addHeader(fmt::format("uuid: {}", clientId));
        _clientIdProvided = true;
        spdlog::debug("UUID(clientId) is provided as {}, hence we wont look for cert+key", clientId);
        initializeLibCurl();
    }

    Connection::Connection(std::string baseUrl) : hCurl(nullptr), _baseUrl(std::move(baseUrl))
    {
        initializeLibCurl();
    }

    void Connection::initializeLibCurl()
    {
        //////////////////////////////
        // Initialise libcurl
        //////////////////////////////
        // In windows, this will init the winsock stuff
        {
            // This global initialisation function is not thread-safe, so we should use a mutex
            // Of course this won't help if anything external to this class tries calling this at the same time
            // but there's not much we can do about that
            std::scoped_lock<std::mutex> guard(_initMutex);
            curl_global_init(CURL_GLOBAL_ALL);
        }

        hCurl = curl_easy_init();
        if (!hCurl)
        {
            spdlog::trace("ERROR: Library initialisation failed");
            throw ApiError("ERROR: Library initialisation failed");
        }

        setUpConnection();
    }

    Connection::~Connection()
    {
        curl_slist_free_all(curlHeaders);
        curl_easy_cleanup(hCurl);

        {
            // This global cleanup function is not thread-safe, so we should use a mutex
            std::scoped_lock<std::mutex> guard(_initMutex);
            curl_global_cleanup();
        }
    }

    Connection::Connection(Connection &&other) noexcept
        : hCurl(std::exchange(other.hCurl, nullptr)), curlHeaders(std::exchange(other.curlHeaders, nullptr)), _baseUrl(std::move(other._baseUrl)),
          _certificate(std::move(other._certificate)), _certType(std::move(other._certType)), _privateKeyForCert(std::move(other._privateKeyForCert)),
          _curlErrorBuffer(other._curlErrorBuffer), _headers(std::move(other._headers)), _inMemory(other._inMemory), _clientIdProvided(other._clientIdProvided)
    {
        // The error buffer pointer needs to be updated to point to the new instance's buffer
        setCurlOption(CURLOPT_ERRORBUFFER, _curlErrorBuffer.data());
    }

    Connection &Connection::operator=(Connection &&other) noexcept
    {
        if (this != &other)
        {
            curl_slist_free_all(curlHeaders);
            curl_easy_cleanup(hCurl);

            hCurl              = std::exchange(other.hCurl, nullptr);
            curlHeaders        = std::exchange(other.curlHeaders, nullptr);
            _baseUrl           = std::move(other._baseUrl);
            _certificate       = std::move(other._certificate);
            _certType          = std::move(other._certType);
            _privateKeyForCert = std::move(other._privateKeyForCert);
            _curlErrorBuffer   = other._curlErrorBuffer;
            _headers           = std::move(other._headers);
            _clientIdProvided  = other._clientIdProvided;
            _inMemory          = other._inMemory;

            // The error buffer pointer needs to be updated to point to the new instance's buffer
            setCurlOption(CURLOPT_ERRORBUFFER, _curlErrorBuffer.data());
        }

        return *this;
    }

    void Connection::addHeader(const std::string &header)
    {
        _headers.push_back(header);
        curlHeaders = curl_slist_append(curlHeaders, _headers.back().c_str());
    }

    void Connection::setProxy(const std::string &proxy)
    {
        setCurlOption(CURLOPT_PROXY, proxy.c_str());
        setCurlOption(CURLOPT_HTTPPROXYTUNNEL, 1L);
    }

    void Connection::setTimeout(long timeout)
    {
        setCurlOption(CURLOPT_TIMEOUT, timeout);
    }

    void Connection::setConnectTimeout(long timeout)
    {
        setCurlOption(CURLOPT_CONNECTTIMEOUT, timeout);
    }

    void Connection::setNativeCa(bool enabled)
    {
        if (enabled)
        {
#ifdef WIN32
            setCurlOption(CURLOPT_SSL_OPTIONS, CURLSSLOPT_NATIVE_CA);
#endif
        }
        else
        {
            // We don't currently use any of the other CURLOPT_SSL_OPTIONS, so we don't need to worry
            // about preserving any other bits that may be set in the bitmask.
            setCurlOption(CURLOPT_SSL_OPTIONS, 0);
        }
    }

    void Connection::setCaBundleFile(const std::string &filename)
    {
        setCurlOption(CURLOPT_CAINFO, filename.c_str());
    }

    template <typename T>
    void Connection::setCurlOption(CURLoption option, T parameter)
    {
        auto rv = curl_easy_setopt(hCurl, option, parameter);
        if (rv != CURLE_OK)
        {
            throw CurlError(rv, _curlErrorBuffer.data());
        }
    }

    static size_t keyResponseHandler(char *buffer, size_t size, size_t nmemb, void *userp)
    {
        // Cast our userp back to its original (KeyResponse *) type
        auto pKeyResponse = static_cast<std::vector<std::string> *>(userp);
        if (!pKeyResponse)
        {
            spdlog::error("keyResponseHandler() UserData is NULL");
            return 0; // Zero bytes processed
        }

        // In case the response is sent in multiple packets, we push all into rawContent for processing it later.
        pKeyResponse->emplace_back(buffer, size * nmemb);

        // Job done
        return size * nmemb; // Number of bytes processed
    }

    void Connection::setUpConnection()
    {
        // Provide a buffer to store errors in
        setCurlOption(CURLOPT_ERRORBUFFER, _curlErrorBuffer.data());

        // Disable usage of signals which can cause crashes
        setCurlOption(CURLOPT_NOSIGNAL, 1L);

        setCurlOption(CURLOPT_HTTPPOST, true);
        addHeader("Content-Type: application/json");
        addHeader("Accept: application/json");

        setCurlOption(CURLOPT_HTTPHEADER, curlHeaders);

        setCurlOption(CURLOPT_WRITEFUNCTION, &keyResponseHandler);
        setCurlOption(CURLOPT_FAILONERROR, true);
        setCurlOption(CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
        setCurlOption(CURLOPT_SSL_VERIFYPEER, 1); // Ensures the server certificate is valid
        setCurlOption(CURLOPT_SSL_VERIFYHOST, 2); // Ensure the certificate hostname matches the host we're connecting to
#ifdef WIN32
        // Under windows, without the below option set, we are unable to load PEM cert+keys (we get curl(60) error), as libcurl defaults to openssl.
        // Another alternative is to enable schannel option on libcurl and import .pfx client cert with MMC then load it using cert store + thumbprint
        //     setCurlOption(CURLOPT_KEYPASSWD, "<pfx pass here>");
        //     setCurlOption(CURLOPT_SSLCERT,"LocalMachine\\my\\3B9DDE4E7EA8A8B0EC91F73659AF225F4E841118");
        setNativeCa(true);
#endif
        // if clientId is provided, we wont use cert + key
        if (!_clientIdProvided && _certificate && _certType && _privateKeyForCert)
        {
            if (_inMemory)
            {
                curl_blob sslCertBlob = {nullptr, 0, 0};
                sslCertBlob.data      = _certificate->data();
                sslCertBlob.len       = _certificate->size();
                sslCertBlob.flags     = CURL_BLOB_COPY;

                curl_blob sslKeyBlob = {nullptr, 0, 0};
                sslKeyBlob.data      = _privateKeyForCert->data();
                sslKeyBlob.len       = _privateKeyForCert->size();
                sslKeyBlob.flags     = CURL_BLOB_COPY;

                setCurlOption(CURLOPT_SSLCERT_BLOB, &sslCertBlob); // Load the certificate
                setCurlOption(CURLOPT_SSLKEY_BLOB, &sslKeyBlob);
            }
            else
            {
                spdlog::debug("Loading files cert [{}] and key [{}]", _certificate->c_str(), _privateKeyForCert->c_str());
                setCurlOption(CURLOPT_SSLCERT, _certificate->c_str()); // Load the certificate
                setCurlOption(CURLOPT_SSLKEY, _privateKeyForCert->c_str());
            }

            setCurlOption(CURLOPT_SSLCERTTYPE, _certType->c_str()); // Load the certificate type
        }
    }

    std::vector<std::string> Connection::sendImpl(const Request &request)
    {
        std::vector<std::string> rawResponse;
        setCurlOption(CURLOPT_WRITEDATA, &rawResponse);

        // check if we are going a post or a get.
        if (request.getMethod() == httpMethod::GET)
        {
            setCurlOption(CURLOPT_HTTPGET, 1L);
            auto url = fmt::format("{}/{}?{}", _baseUrl, request.getEndpoint(), request.exportQuery());
            setCurlOption(CURLOPT_URL, url.c_str());

            spdlog::debug("Making request to '{}'", url);

            if (_certType && _certificate && _privateKeyForCert)
            {
                spdlog::trace("GETing from [{}] using [ CRT:{}, KEY:{}]", url, *_certType, *_certificate, *_privateKeyForCert);

                spdlog::trace(
                    "Curl equivalent might be: curl --verbose -s -X GET --header '{}' --header '{}' --cert {} --key {} \"{}\"", "Content-Type: application/json",
                    "Accept: application/json", *_certificate, *_privateKeyForCert, url);
            }
            runCurl();
        }
        else
        {
            auto url = fmt::format("{}/{}", _baseUrl, request.getEndpoint());
            setCurlOption(CURLOPT_URL, url.c_str());

            spdlog::debug("Making request to '{}'", url);
            setCurlOption(CURLOPT_HTTPPOST, true);
            auto bodyData = request.exportPayloadAsJson().dump();

            setCurlOption(CURLOPT_POSTFIELDS, bodyData.data());
            if (_certType && _certificate && _privateKeyForCert)
            {
                spdlog::trace("POSTing [{}] to [{}] using [TYP:{}, CRT:{}, KEY:{}]", bodyData.data(), url, *_certType, *_certificate, *_privateKeyForCert);

                spdlog::trace(
                    "Curl equivalent might be: curl --verbose -s -X POST --header '{}' --header '{}' --cert {} --key {} --data-raw '{}' {}",
                    "Content-Type: application/json", "Accept: application/json", *_certificate, *_privateKeyForCert, bodyData.data(), url);
            }
            runCurl();
        }
        return rawResponse;
    }

    void Connection::runCurl()
    {
        // Actual HTTP action.
        auto rv = curl_easy_perform(hCurl);
        if (rv != CURLE_OK)
        {
            if (rv == CURLE_HTTP_RETURNED_ERROR)
            {
                // Get the HTTP response code
                long httpResponseCode = 0;
                rv                    = curl_easy_getinfo(hCurl, CURLINFO_RESPONSE_CODE, &httpResponseCode);
                if (rv == CURLE_OK)
                {
                    throw HttpErrorCode(httpResponseCode);
                }
            }

            throw CurlError(rv, _curlErrorBuffer.data());
        }

        // Get the HTTP response code
        long httpResponseCode = 0;
        rv                    = curl_easy_getinfo(hCurl, CURLINFO_RESPONSE_CODE, &httpResponseCode);
        if (rv != CURLE_OK)
        {
            throw CurlError(rv, _curlErrorBuffer.data());
        }

        if (httpResponseCode < 200 || httpResponseCode > 299)
        {
            throw HttpErrorCode(httpResponseCode);
        }
    }

} // namespace Quantinuum::QuantumOrigin::Common
