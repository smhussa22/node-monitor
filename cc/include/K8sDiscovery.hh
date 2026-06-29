#ifndef NODE_MONITOR_K8S_DISCOVERY_HH
#define NODE_MONITOR_K8S_DISCOVERY_HH

// related headers
#include "K8sClient.hh"

// c sys headers

// cpp stdlib headers
#include <string>
#include <vector>

// 3rd party headers

// project headers

namespace NodeMonitor
{

    // minimal pod descriptor returned by the discovery helper. enough for the SnmpPoller to register a
    // target (ip + a logical name for the dashboard); skips spec / status fields we don't currently care
    // about. ready=true means at least one container in the pod is in the Ready=true condition
    struct DiscoveredPod
    {

        std::string m_name { };       // pod metadata.name
        std::string m_namespace { };  // pod metadata.namespace
        std::string m_ip { };         // pod status.podIP; empty until kubernetes assigns one
        bool m_ready { false };       // any container condition Ready=True

    };

    // call the kubernetes API and return every pod matching the label selector in the given namespace.
    // dry-run clients short-circuit to an empty list so the caller can run the same code path locally.
    // any HTTP / parse failure also returns an empty list with a one-line stderr message — the caller
    // (SnmpPoller) treats discovery as best-effort and falls back to whatever it already had registered
    std::vector<DiscoveredPod> discover_pods(K8sClient& client, const std::string& namespace_, const std::string& label_selector);

}

#endif // NODE_MONITOR_K8S_DISCOVERY_HH
