// related headers
#include "AclRule.hh"

// c sys headers
#include <arpa/inet.h>

// cpp stdlib headers
#include <cctype>
#include <cstdint>
#include <format>
#include <stdexcept>
#include <string>

// 3rd party headers

// project headers

namespace NodeMonitor
{

    // case-insensitive trim+lower used by the small parser helpers below; kept local
    namespace
    {

        std::string to_lower_trimmed(const std::string& s)
        {

            std::string out { };
            out.reserve(s.size());
            for (char c : s)
            {
                if (c == ' ' || c == '\t') continue;
                out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
            }
            return out;

        }

    }

    // ----- CidrMatcher -----

    bool CidrMatcher::matches(std::uint32_t addr) const noexcept
    {

        // mask 0 acts as wildcard so "any" rules short-circuit without touching addr bits
        if (m_mask == 0u) return true;
        return (addr & m_mask) == m_network;

    }

    // ----- PortRange -----

    bool PortRange::matches(std::uint16_t port) const noexcept
    {

        return port >= m_lo && port <= m_hi;

    }

    // ----- parsers -----

    std::uint32_t ipv4_to_uint(const std::string& dotted)
    {

        if (dotted.empty()) throw std::invalid_argument { "ipv4_to_uint: empty input" };

        std::uint32_t out_be { 0 };
        int rc { ::inet_pton(AF_INET, dotted.c_str(), &out_be) };
        if (rc != 1) throw std::invalid_argument { std::format("ipv4_to_uint: not a valid ipv4 address: '{}'", dotted) };

        // inet_pton writes network byte order; the engine works in host byte order so we flip here
        return ntohl(out_be);

    }

    CidrMatcher parse_cidr(const std::string& spec)
    {

        std::string normalized { to_lower_trimmed(spec) };
        if (normalized == "any" || normalized == "*") return CidrMatcher { 0u, 0u, 0u };

        // split "<addr>/<prefix>"; a missing slash is treated as a /32 host route
        std::size_t slash { normalized.find('/') };
        std::string addr_part { slash == std::string::npos ? normalized : normalized.substr(0, slash) };
        std::string prefix_part { slash == std::string::npos ? std::string { "32" } : normalized.substr(slash + 1) };

        std::uint32_t addr { ipv4_to_uint(addr_part) };

        int prefix_len { 0 };
        try
        {
            prefix_len = std::stoi(prefix_part);
        }
        catch (const std::exception&)
        {
            throw std::invalid_argument { std::format("parse_cidr: invalid prefix length in '{}'", spec) };
        }
        if (prefix_len < 0 || prefix_len > 32) throw std::invalid_argument { std::format("parse_cidr: prefix length out of range in '{}'", spec) };

        // prefix 0 means "any"; build the network mask carefully because shifting by 32 is UB on uint32_t
        std::uint32_t mask { prefix_len == 0 ? 0u : (0xFFFFFFFFu << (32 - prefix_len)) };

        // mask the network so callers can write "10.1.2.3/8" and we treat it as "10.0.0.0/8"
        return CidrMatcher { addr & mask, mask, static_cast<std::uint8_t>(prefix_len) };

    }

    PortRange parse_port_range(const std::string& spec)
    {

        std::string normalized { to_lower_trimmed(spec) };
        if (normalized == "any" || normalized == "*") return PortRange { 0u, 65535u };

        std::size_t dash { normalized.find('-') };

        // single port "80" expands to [80, 80]
        if (dash == std::string::npos)
        {
            int port { 0 };
            try { port = std::stoi(normalized); }
            catch (const std::exception&) { throw std::invalid_argument { std::format("parse_port_range: invalid port '{}'", spec) }; }
            if (port < 0 || port > 65535) throw std::invalid_argument { std::format("parse_port_range: port out of range in '{}'", spec) };
            return PortRange { static_cast<std::uint16_t>(port), static_cast<std::uint16_t>(port) };
        }

        int lo { 0 };
        int hi { 0 };
        try
        {
            lo = std::stoi(normalized.substr(0, dash));
            hi = std::stoi(normalized.substr(dash + 1));
        }
        catch (const std::exception&)
        {
            throw std::invalid_argument { std::format("parse_port_range: malformed range '{}'", spec) };
        }
        if (lo < 0 || hi < 0 || lo > 65535 || hi > 65535) throw std::invalid_argument { std::format("parse_port_range: range out of bounds in '{}'", spec) };
        if (lo > hi) throw std::invalid_argument { std::format("parse_port_range: lo > hi in '{}'", spec) };

        return PortRange { static_cast<std::uint16_t>(lo), static_cast<std::uint16_t>(hi) };

    }

    AclProtocol parse_protocol(const std::string& spec)
    {

        std::string normalized { to_lower_trimmed(spec) };
        if (normalized == "any" || normalized == "*") return AclProtocol::Any;
        if (normalized == "tcp") return AclProtocol::Tcp;
        if (normalized == "udp") return AclProtocol::Udp;
        if (normalized == "icmp") return AclProtocol::Icmp;
        throw std::invalid_argument { std::format("parse_protocol: unknown protocol '{}'", spec) };

    }

    // ----- to_string overloads -----

    std::string to_string(AclAction action)
    {

        return action == AclAction::Permit ? "permit" : "deny";

    }

    std::string to_string(AclProtocol protocol)
    {

        switch (protocol)
        {
            case AclProtocol::Any: return "any";
            case AclProtocol::Tcp: return "tcp";
            case AclProtocol::Udp: return "udp";
            case AclProtocol::Icmp: return "icmp";
        }
        return "any";

    }

    std::string to_string(const CidrMatcher& cidr)
    {

        if (cidr.m_mask == 0u) return "any";

        // unpack host-byte-order back to dotted-quad without pulling inet_ntop in; trivial enough
        std::uint32_t a { cidr.m_network };
        return std::format("{}.{}.{}.{}/{}", (a >> 24) & 0xFFu, (a >> 16) & 0xFFu, (a >> 8) & 0xFFu, a & 0xFFu, cidr.m_prefix_len);

    }

    std::string to_string(const PortRange& ports)
    {

        if (ports.m_lo == 0u && ports.m_hi == 65535u) return "any";
        if (ports.m_lo == ports.m_hi) return std::format("{}", ports.m_lo);
        return std::format("{}-{}", ports.m_lo, ports.m_hi);

    }

    // ----- AclRule -----

    AclRule::AclRule(std::uint32_t id, AclAction action, AclProtocol protocol, CidrMatcher src_cidr, CidrMatcher dst_cidr, PortRange src_ports, PortRange dst_ports, const std::string& description)
        : m_id { id }, m_action { action }, m_protocol { protocol }, m_src_cidr { src_cidr }, m_dst_cidr { dst_cidr }, m_src_ports { src_ports }, m_dst_ports { dst_ports }, m_description { description }
    {

    }

    bool AclRule::matches(std::uint32_t src_ip, std::uint32_t dst_ip, std::uint16_t src_port, std::uint16_t dst_port, AclProtocol protocol) const noexcept
    {

        // protocol-specific rules ignore the port columns for icmp because icmp has no ports.
        // a rule with AclProtocol::Any matches any protocol so we just check the cidrs + ports
        if (m_protocol != AclProtocol::Any && m_protocol != protocol) return false;
        if (!m_src_cidr.matches(src_ip)) return false;
        if (!m_dst_cidr.matches(dst_ip)) return false;

        // icmp has no port concept; ignore the port-range columns when the flow is icmp
        if (protocol == AclProtocol::Icmp) return true;

        if (!m_src_ports.matches(src_port)) return false;
        if (!m_dst_ports.matches(dst_port)) return false;
        return true;

    }

    void AclRule::record_hit() noexcept
    {

        m_hits.fetch_add(1uz, std::memory_order_relaxed);

    }

    std::uint32_t AclRule::id() const noexcept
    {

        return m_id;

    }

    AclAction AclRule::action() const noexcept
    {

        return m_action;

    }

    AclProtocol AclRule::protocol() const noexcept
    {

        return m_protocol;

    }

    const CidrMatcher& AclRule::src_cidr() const noexcept
    {

        return m_src_cidr;

    }

    const CidrMatcher& AclRule::dst_cidr() const noexcept
    {

        return m_dst_cidr;

    }

    const PortRange& AclRule::src_ports() const noexcept
    {

        return m_src_ports;

    }

    const PortRange& AclRule::dst_ports() const noexcept
    {

        return m_dst_ports;

    }

    const std::string& AclRule::description() const noexcept
    {

        return m_description;

    }

    std::uint64_t AclRule::hits() const noexcept
    {

        return m_hits.load(std::memory_order_relaxed);

    }

}
