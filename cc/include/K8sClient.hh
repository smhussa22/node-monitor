#ifndef NODE_MONITOR_K8S_CLIENT_HH
#define NODE_MONITOR_K8S_CLIENT_HH

// related headers

// c sys headers

// cpp stdlib headers
#include <memory>
#include <string>

// 3rd party headers

// project headers

namespace NodeMonitor
{

    // HTTP response from a single k8s API call
    struct K8sResponse
    {

        long m_status_code { 0 }; // HTTP status; 0 if the request never went out (e.g. dry-run mode)
        std::string m_body { };   // response body, possibly empty
        std::string m_error { };  // libcurl error string on transport failure

    };

    // minimal authenticated HTTP client for talking to the kubernetes API server
    class K8sClient
    {

    public:

        K8sClient() = delete;

        // explicit constructor for real use against a kubernetes API server.
        // api_url is the base url (e.g. "https://kubernetes.default.svc"),
        // token is the bearer token, ca_cert_path is a filesystem path to the CA bundle (empty disables TLS verification).
        K8sClient(const std::string& api_url, const std::string& token, const std::string& ca_cert_path, bool dry_run);
        ~K8sClient();

        K8sClient(const K8sClient&) = delete;
        K8sClient& operator=(const K8sClient&) = delete;
        K8sClient(K8sClient&&) = delete;
        K8sClient& operator=(K8sClient&&) = delete;

        K8sResponse get(const std::string& path);
        K8sResponse del(const std::string& path);
        K8sResponse patch(const std::string& path, const std::string& json_body, const std::string& content_type);
        K8sResponse post(const std::string& path, const std::string& json_body);

        bool is_dry_run() const noexcept;
        std::string api_url() const;

        // factory: detect in-cluster mode from /var/run/secrets/kubernetes.io/serviceaccount/{token,ca.crt}.
        // returns a constructed client in real mode if those files exist; otherwise returns a dry-run client
        // configured with a placeholder URL so callers never have to null-check. log via std::println which mode was chosen.
        static std::unique_ptr<K8sClient> create_from_environment();

    private:

        // common path: build a curl handle, set headers, run, capture response. used by all four verbs.
        K8sResponse perform_request(const std::string& method, const std::string& path, const std::string& body, const std::string& content_type);

        std::string m_api_url { };      // base url of the api server, e.g. "https://kubernetes.default.svc"
        std::string m_token { };        // bearer token used for the Authorization header
        std::string m_ca_cert_path { }; // path to a CA bundle on disk; empty disables TLS verification
        bool m_dry_run { false };       // when true no HTTP request is issued and a zero-status response is returned

    };

}

#endif // NODE_MONITOR_K8S_CLIENT_HH
