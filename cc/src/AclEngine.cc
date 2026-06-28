// related headers
#include "AclEngine.hh"

// c sys headers

// cpp stdlib headers
#include <cstdint>
#include <exception>
#include <memory>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

// 3rd party headers
#include <nlohmann/json.hpp>

// project headers

namespace NodeMonitor
{

    void AclEngine::register_rule(std::unique_ptr<AclRule> rule)
    {

        if (rule == nullptr) return;

        std::lock_guard<std::mutex> lock { m_mutex };
        m_rules.push_back(std::move(rule));

    }

    AclVerdict AclEngine::evaluate(std::uint32_t src_ip, std::uint32_t dst_ip, std::uint16_t src_port, std::uint16_t dst_port, AclProtocol protocol)
    {

        m_evaluations.fetch_add(1uz, std::memory_order_relaxed);

        // hold the lock for the duration of the walk; rules are append-only and the list is small,
        // so the contention is negligible vs. the cost of copying the rule list per evaluate call
        std::lock_guard<std::mutex> lock { m_mutex };

        for (const auto& rule_ptr : m_rules)
        {

            if (!rule_ptr->matches(src_ip, dst_ip, src_port, dst_port, protocol)) continue;

            // first match wins; bump the rule's hit counter and the appropriate engine total
            rule_ptr->record_hit();
            if (rule_ptr->action() == AclAction::Permit) m_permits.fetch_add(1uz, std::memory_order_relaxed);
            else m_denies.fetch_add(1uz, std::memory_order_relaxed);

            return AclVerdict { rule_ptr->action(), static_cast<std::int32_t>(rule_ptr->id()) };

        }

        // no rule matched; standard router behavior is "implicit deny at end of list"
        m_implicit_denies.fetch_add(1uz, std::memory_order_relaxed);
        return AclVerdict { AclAction::Deny, -1 };

    }

    AclVerdict AclEngine::evaluate(const ::nlohmann::json& flow)
    {

        // a malformed netflow record must never crash the receiver; treat it as implicit deny so the
        // caller can still persist it with acl_action='deny' and the operator notices via the dashboard
        try
        {

            const std::string src_ip_str { flow.at("src_ip").get<std::string>() };
            const std::string dst_ip_str { flow.at("dst_ip").get<std::string>() };
            const std::uint16_t src_port { flow.at("src_port").get<std::uint16_t>() };
            const std::uint16_t dst_port { flow.at("dst_port").get<std::uint16_t>() };
            const std::string protocol_str { flow.at("protocol").get<std::string>() };

            std::uint32_t src_ip { ipv4_to_uint(src_ip_str) };
            std::uint32_t dst_ip { ipv4_to_uint(dst_ip_str) };
            AclProtocol protocol { parse_protocol(protocol_str) };

            return evaluate(src_ip, dst_ip, src_port, dst_port, protocol);

        }
        catch (const std::exception&)
        {

            m_evaluations.fetch_add(1uz, std::memory_order_relaxed);
            m_implicit_denies.fetch_add(1uz, std::memory_order_relaxed);
            return AclVerdict { AclAction::Deny, -1 };

        }

    }

    std::uint64_t AclEngine::total_evaluations() const noexcept
    {

        return m_evaluations.load(std::memory_order_relaxed);

    }

    std::uint64_t AclEngine::total_permits() const noexcept
    {

        return m_permits.load(std::memory_order_relaxed);

    }

    std::uint64_t AclEngine::total_denies() const noexcept
    {

        return m_denies.load(std::memory_order_relaxed);

    }

    std::uint64_t AclEngine::implicit_denies() const noexcept
    {

        return m_implicit_denies.load(std::memory_order_relaxed);

    }

    std::size_t AclEngine::rule_count() const
    {

        std::lock_guard<std::mutex> lock { m_mutex };
        return m_rules.size();

    }

    std::vector<AclRuleSnapshot> AclEngine::snapshot() const
    {

        std::vector<AclRuleSnapshot> out { };

        std::lock_guard<std::mutex> lock { m_mutex };
        out.reserve(m_rules.size());

        for (const auto& rule_ptr : m_rules)
        {

            out.push_back(AclRuleSnapshot {
                rule_ptr->id(),
                to_string(rule_ptr->action()),
                to_string(rule_ptr->protocol()),
                to_string(rule_ptr->src_cidr()),
                to_string(rule_ptr->dst_cidr()),
                to_string(rule_ptr->src_ports()),
                to_string(rule_ptr->dst_ports()),
                rule_ptr->description(),
                rule_ptr->hits()
            });

        }

        return out;

    }

}
