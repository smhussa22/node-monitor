#ifndef NODE_MONITOR_ACL_ENGINE_HH
#define NODE_MONITOR_ACL_ENGINE_HH

// related headers
#include "AclRule.hh"

// c sys headers

// cpp stdlib headers
#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

// 3rd party headers
#include <nlohmann/json.hpp>

// project headers

namespace NodeMonitor
{

    // result of evaluating one flow against the rule list; m_rule_id == -1 means implicit deny
    struct AclVerdict
    {

        AclAction m_action { AclAction::Deny }; // permit when a rule matched and said permit; deny otherwise
        std::int32_t m_rule_id { -1 };          // matched rule id, or -1 when no rule matched

    };

    // snapshot of one rule's runtime state; copied out of the engine so the dashboard can render
    // it without holding the engine lock or the atomic counter
    struct AclRuleSnapshot
    {

        std::uint32_t m_id { 0 };       // stable rule identifier; same one stored in flows.acl_rule_id
        std::string m_action { };       // "permit" / "deny"
        std::string m_protocol { };     // "tcp" / "udp" / "icmp" / "any"
        std::string m_src_cidr { };     // e.g. "10.0.0.0/8" or "any"
        std::string m_dst_cidr { };     // e.g. "8.8.8.8/32" or "any"
        std::string m_src_ports { };    // e.g. "1024-65535" or "any"
        std::string m_dst_ports { };    // e.g. "22" or "80-443" or "any"
        std::string m_description { };  // short human-readable label
        std::uint64_t m_hits { 0 };     // monotonic match count at snapshot time

    };

    // evaluates netflow records against an ordered acl list with first-match-wins semantics. rules
    // are registered at startup and read on every flow; an internal mutex makes register / evaluate
    // safe to call concurrently
    class AclEngine
    {

    public:

        AclEngine() = default;
        ~AclEngine() = default;

        AclEngine(const AclEngine&) = delete;
        AclEngine& operator=(const AclEngine&) = delete;
        AclEngine(AclEngine&&) = delete;
        AclEngine& operator=(AclEngine&&) = delete;

        // take ownership of one rule and append it to the end of the ordered list
        void register_rule(std::unique_ptr<AclRule> rule);

        // walk the rule list; first match wins. when no rule matches, returns implicit-deny
        // (m_action == Deny, m_rule_id == -1). bumps the matched rule's hit counter and the
        // appropriate engine-wide totals
        AclVerdict evaluate(std::uint32_t src_ip, std::uint32_t dst_ip, std::uint16_t src_port, std::uint16_t dst_port, AclProtocol protocol);

        // convenience overload that pulls the 5-tuple out of a netflow json record produced by
        // the cisco simulator (fields: src_ip, dst_ip, src_port, dst_port, protocol). returns
        // implicit-deny on a malformed record so the receiver path never crashes on bad input
        AclVerdict evaluate(const ::nlohmann::json& flow);

        std::uint64_t total_evaluations() const noexcept;
        std::uint64_t total_permits() const noexcept;
        std::uint64_t total_denies() const noexcept;
        std::uint64_t implicit_denies() const noexcept;
        std::size_t rule_count() const;

        // copies every rule's display fields + current hit count into a snapshot vector; the engine
        // lock is held only for the iteration so callers can render at will
        std::vector<AclRuleSnapshot> snapshot() const;

    private:

        std::vector<std::unique_ptr<AclRule>> m_rules { }; // ordered rule list; first-match-wins
        mutable std::mutex m_mutex { };                    // guards m_rules from concurrent register / evaluate / snapshot
        std::atomic<std::uint64_t> m_evaluations { 0 };    // total flows evaluated
        std::atomic<std::uint64_t> m_permits { 0 };        // flows that matched a permit rule
        std::atomic<std::uint64_t> m_denies { 0 };         // flows that matched a deny rule
        std::atomic<std::uint64_t> m_implicit_denies { 0 }; // flows that fell through to implicit deny

    };

}

#endif // NODE_MONITOR_ACL_ENGINE_HH
