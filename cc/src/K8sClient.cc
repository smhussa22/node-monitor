// related headers
#include "K8sClient.hh"

// c sys headers
#include <curl/curl.h>

// cpp stdlib headers
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <memory>
#include <print>
#include <sstream>
#include <string>

// 3rd party headers

// project headers

namespace NodeMonitor
{

    namespace
    {

        // libcurl write callback that appends received bytes to a std::string passed via CURLOPT_WRITEDATA
        std::size_t curl_write_callback(char* ptr, std::size_t size, std::size_t nmemb, void* userdata)
        {

            std::size_t total { size * nmemb };
            std::string* out { static_cast<std::string*>(userdata) };
            if (out != nullptr) out->append(ptr, total);
            return total;

        }

        // read the entire contents of a file and strip trailing whitespace (newlines, spaces)
        std::string read_file_trimmed(const std::string& path)
        {

            std::ifstream stream { path };
            if (!stream.is_open()) return std::string { };

            std::stringstream buffer { };
            buffer << stream.rdbuf();
            std::string contents { buffer.str() };

            while (!contents.empty() && (contents.back() == '\n' || contents.back() == '\r' || contents.back() == ' ' || contents.back() == '\t'))
            {

                contents.pop_back();

            }

            return contents;

        }

    }

    K8sClient::K8sClient(const std::string& api_url, const std::string& token, const std::string& ca_cert_path, bool dry_run)
        : m_api_url { api_url }
        , m_token { token }
        , m_ca_cert_path { ca_cert_path }
        , m_dry_run { dry_run }
    {

    }

    K8sClient::~K8sClient()
    {

    }

    K8sResponse K8sClient::get(const std::string& path)
    {

        return perform_request("GET", path, std::string { }, std::string { });

    }

    K8sResponse K8sClient::del(const std::string& path)
    {

        return perform_request("DELETE", path, std::string { }, std::string { });

    }

    K8sResponse K8sClient::patch(const std::string& path, const std::string& json_body, const std::string& content_type)
    {

        return perform_request("PATCH", path, json_body, content_type);

    }

    K8sResponse K8sClient::post(const std::string& path, const std::string& json_body)
    {

        return perform_request("POST", path, json_body, "application/json");

    }

    bool K8sClient::is_dry_run() const noexcept
    {

        return m_dry_run;

    }

    std::string K8sClient::api_url() const
    {

        return m_api_url;

    }

    std::unique_ptr<K8sClient> K8sClient::create_from_environment()
    {

        const std::string token_path { "/var/run/secrets/kubernetes.io/serviceaccount/token" };
        const std::string ca_path { "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt" };

        // honor KUBERNETES_DRY_RUN=true as an override even if the token exists
        const char* override_env { std::getenv("KUBERNETES_DRY_RUN") };
        bool force_dry_run { false };
        if (override_env != nullptr)
        {

            std::string value { override_env };
            if (value == "true" || value == "1" || value == "TRUE") force_dry_run = true;

        }

        std::error_code ec { };
        bool token_exists { std::filesystem::exists(token_path, ec) };

        if (token_exists && !force_dry_run)
        {

            std::string token { read_file_trimmed(token_path) };
            std::println("k8s client running against the live cluster API");
            return std::make_unique<K8sClient>("https://kubernetes.default.svc", token, ca_path, false);

        }

        std::println("k8s client running in dry-run mode (no in-cluster credentials found)");
        return std::make_unique<K8sClient>("https://dry-run", std::string { }, std::string { }, true);

    }

    K8sResponse K8sClient::perform_request(const std::string& method, const std::string& path, const std::string& body, const std::string& content_type)
    {

        K8sResponse response { };

        // in dry-run mode no HTTP call is made; record the intent and return a zeroed response
        if (m_dry_run)
        {

            std::println("[k8s] DRY-RUN {} {}", method, path);
            return response;

        }

        // RAII wrapper around the curl easy handle so curl_easy_cleanup always runs
        std::unique_ptr<::CURL, decltype(&::curl_easy_cleanup)> curl { ::curl_easy_init(), &::curl_easy_cleanup };
        if (curl == nullptr)
        {

            response.m_error = "curl_easy_init failed";
            return response;

        }

        // build the full url and configure verb + timeout
        std::string url { m_api_url + path };
        ::curl_easy_setopt(curl.get(), ::CURLOPT_URL, url.c_str());
        ::curl_easy_setopt(curl.get(), ::CURLOPT_CUSTOMREQUEST, method.c_str());
        ::curl_easy_setopt(curl.get(), ::CURLOPT_TIMEOUT, 10L);

        // build the header list inside an RAII wrapper so curl_slist_free_all always runs
        std::unique_ptr<::curl_slist, decltype(&::curl_slist_free_all)> headers { nullptr, &::curl_slist_free_all };
        {

            ::curl_slist* raw { nullptr };
            std::string auth_header { "Authorization: Bearer " + m_token };
            raw = ::curl_slist_append(raw, auth_header.c_str());
            raw = ::curl_slist_append(raw, "Accept: application/json");
            if (!content_type.empty())
            {

                std::string ct_header { "Content-Type: " + content_type };
                raw = ::curl_slist_append(raw, ct_header.c_str());

            }
            headers.reset(raw);

        }
        ::curl_easy_setopt(curl.get(), ::CURLOPT_HTTPHEADER, headers.get());

        // attach the request body when present
        if (!body.empty())
        {

            ::curl_easy_setopt(curl.get(), ::CURLOPT_POSTFIELDS, body.c_str());
            ::curl_easy_setopt(curl.get(), ::CURLOPT_POSTFIELDSIZE_LARGE, static_cast<::curl_off_t>(body.size()));

        }

        // configure TLS verification based on whether a CA bundle path was supplied
        if (!m_ca_cert_path.empty())
        {

            ::curl_easy_setopt(curl.get(), ::CURLOPT_CAINFO, m_ca_cert_path.c_str());

        }
        else
        {

            ::curl_easy_setopt(curl.get(), ::CURLOPT_SSL_VERIFYPEER, 0L);
            ::curl_easy_setopt(curl.get(), ::CURLOPT_SSL_VERIFYHOST, 0L);

        }

        // wire the write callback to append response bytes into response.m_body
        ::curl_easy_setopt(curl.get(), ::CURLOPT_WRITEFUNCTION, curl_write_callback);
        ::curl_easy_setopt(curl.get(), ::CURLOPT_WRITEDATA, &response.m_body);

        // perform the request and capture transport errors / HTTP status
        ::CURLcode rc { ::curl_easy_perform(curl.get()) };
        if (rc != ::CURLE_OK) response.m_error = ::curl_easy_strerror(rc);

        long status_code { 0 };
        ::curl_easy_getinfo(curl.get(), ::CURLINFO_RESPONSE_CODE, &status_code);
        response.m_status_code = status_code;

        return response;

    }

}
