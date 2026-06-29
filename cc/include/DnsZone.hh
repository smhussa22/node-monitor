#ifndef NODE_MONITOR_DNS_ZONE_HH
#define NODE_MONITOR_DNS_ZONE_HH

// related headers

// c sys headers

// cpp stdlib headers
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

// 3rd party headers

// project headers

namespace NodeMonitor
{

    // one (hostname, ip) binding as exposed to the dashboard. names are stored fully-qualified including
    // the zone suffix so the snapshot is ready to render without re-assembly
    struct DnsZoneEntry
    {

        std::string m_fqdn { };          // e.g. "router-3.node-monitor.local"
        std::uint32_t m_ip { 0 };        // host byte order ipv4
        std::string m_source { };        // tag describing where the entry came from: "dhcp" / "static"

    };

    // tiny authoritative zone used by the DnsServer to answer A + PTR queries. populated by the DhcpServer
    // on every ACK / RELEASE / expiry, so the zone is a live mirror of the lease table. lookup uses
    // case-insensitive name comparison because DNS names are case-insensitive per RFC 1035 section 2.3.3
    class DnsZone
    {

    public:

        DnsZone() = delete;
        explicit DnsZone(const std::string& suffix);
        ~DnsZone() = default;

        DnsZone(const DnsZone&) = delete;
        DnsZone& operator=(const DnsZone&) = delete;
        DnsZone(DnsZone&&) = delete;
        DnsZone& operator=(DnsZone&&) = delete;

        // bind <short_name>.<suffix> -> ip; overwrites any prior binding for the same name. updates both
        // the forward and reverse maps. m_source labels where the binding came from for the dashboard
        void bind(const std::string& short_name, std::uint32_t ip, const std::string& source);

        // remove the binding for short_name if any; also clears the corresponding reverse entry
        void unbind(const std::string& short_name);

        // ipv4 lookup by fqdn (case-insensitive). returns nullopt when the name is outside our zone or
        // not bound
        std::optional<std::uint32_t> lookup_a(const std::string& fqdn) const;

        // AAAA lookup: synthesizes an IPv4-mapped IPv6 address (::ffff:a.b.c.d, RFC 4291 §2.5.5.2) from
        // the bound IPv4 entry. returns the 16-byte rdata ready to drop into a DnsRR, or nullopt when the
        // host has no A binding. avoids us having to maintain a parallel IPv6 map — every device that
        // joins the zone via DHCP gets a corresponding AAAA for free
        std::optional<std::vector<std::uint8_t>> lookup_aaaa(const std::string& fqdn) const;

        // reverse lookup: given a "<reversed-octets>.in-addr.arpa" name, return the fqdn that owns the ip
        std::optional<std::string> lookup_ptr(const std::string& arpa_name) const;

        // returns true when the queried name's lowercase form ends with our zone suffix (with a leading
        // dot), so the DnsServer can answer REFUSED for anything outside the zone
        bool covers(const std::string& fqdn) const;

        const std::string& suffix() const noexcept;

        // snapshot every binding under the lock; copied out so the dashboard can render without holding it
        std::vector<DnsZoneEntry> snapshot() const;

        std::size_t entry_count() const;

    private:

        std::string m_suffix { };                                       // zone suffix, e.g. "node-monitor.local"
        std::unordered_map<std::string, std::uint32_t> m_forward { };   // lowercase fqdn -> ipv4
        std::unordered_map<std::uint32_t, std::string> m_reverse { };   // ipv4 -> fqdn
        std::unordered_map<std::string, std::string> m_sources { };     // fqdn -> source tag for the dashboard
        mutable std::mutex m_mutex { };                                 // guards all three maps

    };

}

#endif // NODE_MONITOR_DNS_ZONE_HH
