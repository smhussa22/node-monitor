// related headers
#include "K8sDiscovery.hh"

// c sys headers

// cpp stdlib headers
#include <print>
#include <string>
#include <vector>

// 3rd party headers
#include <nlohmann/json.hpp>

// project headers

namespace NodeMonitor
{

    std::vector<DiscoveredPod> discover_pods(K8sClient& client, const std::string& namespace_, const std::string& label_selector)
    {

        std::vector<DiscoveredPod> out { };

        // dry-run mode (no in-cluster credentials) has no pods to list; the caller falls back to static targets
        if (client.is_dry_run()) return out;

        // build the standard kubernetes core/v1 pod list path; label selector is the standard k8s
        // SelectorSyntax (key=value pairs joined with commas) and goes in the query string
        std::string path { "/api/v1/namespaces/" + namespace_ + "/pods" };
        if (!label_selector.empty())
        {
            std::string escaped { };
            escaped.reserve(label_selector.size() * 2uz);
            // tiny urlencode covering the bytes the apiserver actually cares about; preserves the chars
            // a label selector usually contains (letters, digits, =, -, ., _, ,)
            for (char c : label_selector)
            {
                if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '=' || c == '-' || c == '.' || c == '_' || c == ',')
                {
                    escaped.push_back(c);
                }
                else
                {
                    char buf[4] { };
                    std::snprintf(buf, sizeof(buf), "%%%02X", static_cast<unsigned char>(c));
                    escaped.append(buf, 3);
                }
            }
            path += "?labelSelector=" + escaped;
        }

        auto resp { client.get(path) };
        if (resp.m_status_code != 200)
        {
            std::println("warn: k8s pod list returned status {} body_len={}", resp.m_status_code, resp.m_body.size());
            return out;
        }

        try
        {
            auto parsed { ::nlohmann::json::parse(resp.m_body) };
            auto items { parsed.find("items") };
            if (items == parsed.end() || !items->is_array()) return out;

            for (const auto& pod : *items)
            {

                DiscoveredPod p { };
                if (auto md { pod.find("metadata") }; md != pod.end())
                {
                    if (auto n { md->find("name") }; n != md->end() && n->is_string()) p.m_name = n->get<std::string>();
                    if (auto ns { md->find("namespace") }; ns != md->end() && ns->is_string()) p.m_namespace = ns->get<std::string>();
                }
                if (auto st { pod.find("status") }; st != pod.end())
                {
                    if (auto ip { st->find("podIP") }; ip != st->end() && ip->is_string()) p.m_ip = ip->get<std::string>();
                    // walk conditions[].type == "Ready" and check status == "True"
                    if (auto conds { st->find("conditions") }; conds != st->end() && conds->is_array())
                    {
                        for (const auto& c : *conds)
                        {
                            auto type { c.find("type") };
                            auto status { c.find("status") };
                            if (type != c.end() && type->is_string() && type->get<std::string>() == "Ready"
                                && status != c.end() && status->is_string() && status->get<std::string>() == "True")
                            {
                                p.m_ready = true;
                                break;
                            }
                        }
                    }
                }

                // skip pods that haven't been scheduled yet (no IP); they'll appear on the next refresh
                if (!p.m_ip.empty()) out.push_back(std::move(p));

            }
        }
        catch (const std::exception& e)
        {
            std::println("warn: k8s pod list parse failed: {}", e.what());
        }

        return out;

    }

}
