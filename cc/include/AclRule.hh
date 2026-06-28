#ifndef NODE_MONITOR_ACL_RULE_HH
#define NODE_MONITOR_ACL_RULE_HH

// related headers

// c sys headers

// cpp stdlib headers
#include <atomic>
#include <cstdint>
#include <string>

// 3rd party headers

// project headers

namespace NodeMonitor
{

    // what to do when a flow matches this rule
    enum class AclAction
    {

        Permit, // allow the flow through; persist with acl_action='permit'
        Deny,   // block the flow; persist with acl_action='deny'

    };

    // ip protocol selector for a single rule; "Any" means the protocol column is wildcarded
    enum class AclProtocol
    {

        Any,
        Tcp,
        Udp,
        Icmp,

    };

    // matches an ipv4 address against a cidr block; network/mask are kept in host byte order so
    // the match is just (addr & mask) == network. mask == 0 means "any address"
    struct CidrMatcher
    {

        std::uint32_t m_network { 0 }; // network address with host bits cleared
        std::uint32_t m_mask { 0 };    // prefix mask; 0x00000000 means wildcard / any
        std::uint8_t m_prefix_len { 0 }; // 0..32; retained for display and dashboard rendering

        // true if addr falls inside the cidr; "any" (mask == 0) matches everything
        bool matches(std::uint32_t addr) const noexcept;

    };

    // inclusive port range; the special pair [0, 65535] is treated as "any"
    struct PortRange
    {

        std::uint16_t m_lo { 0 };     // lowest port that matches (inclusive)
        std::uint16_t m_hi { 65535 }; // highest port that matches (inclusive)

        // true if port lies inside [m_lo, m_hi]
        bool matches(std::uint16_t port) const noexcept;

    };

    // convert a dotted-quad ipv4 string into a host-byte-order uint32; throws std::invalid_argument on bad input
    std::uint32_t ipv4_to_uint(const std::string& dotted);

    // parse "10.0.0.0/8" / "0.0.0.0/0" / "any" into a CidrMatcher; throws on malformed input
    CidrMatcher parse_cidr(const std::string& spec);

    // parse "80" / "1024-65535" / "any" into a PortRange; throws on malformed input
    PortRange parse_port_range(const std::string& spec);

    // parse "TCP" / "UDP" / "ICMP" / "any" (case-insensitive) into an AclProtocol; throws on unknown values
    AclProtocol parse_protocol(const std::string& spec);

    // string forms used by the dashboard snapshot api
    std::string to_string(AclAction action);
    std::string to_string(AclProtocol protocol);
    std::string to_string(const CidrMatcher& cidr);
    std::string to_string(const PortRange& ports);

    // one ordered acl entry; non-copyable / non-movable because it owns an atomic hit counter
    class AclRule
    {

    public:

        AclRule() = delete;
        AclRule(std::uint32_t id, AclAction action, AclProtocol protocol, CidrMatcher src_cidr, CidrMatcher dst_cidr, PortRange src_ports, PortRange dst_ports, const std::string& description);
        ~AclRule() = default;

        AclRule(const AclRule&) = delete;
        AclRule& operator=(const AclRule&) = delete;
        AclRule(AclRule&&) = delete;
        AclRule& operator=(AclRule&&) = delete;

        // pure 5-tuple test; does not mutate the hit counter
        bool matches(std::uint32_t src_ip, std::uint32_t dst_ip, std::uint16_t src_port, std::uint16_t dst_port, AclProtocol protocol) const noexcept;

        // bump the hit counter; AclEngine calls this after a first-match wins
        void record_hit() noexcept;

        std::uint32_t id() const noexcept;
        AclAction action() const noexcept;
        AclProtocol protocol() const noexcept;
        const CidrMatcher& src_cidr() const noexcept;
        const CidrMatcher& dst_cidr() const noexcept;
        const PortRange& src_ports() const noexcept;
        const PortRange& dst_ports() const noexcept;
        const std::string& description() const noexcept;
        std::uint64_t hits() const noexcept;

    private:

        std::uint32_t m_id { 0 };                 // stable rule identifier persisted in flows.acl_rule_id
        AclAction m_action { AclAction::Permit }; // verdict when the 5-tuple matches
        AclProtocol m_protocol { AclProtocol::Any }; // tcp / udp / icmp / any
        CidrMatcher m_src_cidr { };               // matches the source ip
        CidrMatcher m_dst_cidr { };               // matches the destination ip
        PortRange m_src_ports { };                // inclusive source port range
        PortRange m_dst_ports { };                // inclusive destination port range
        std::string m_description { };            // short human-readable label rendered on the dashboard
        std::atomic<std::uint64_t> m_hits { 0 };  // monotonic count of flows that matched this rule

    };

}

#endif // NODE_MONITOR_ACL_RULE_HH
