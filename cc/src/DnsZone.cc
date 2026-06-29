// related headers
#include "DnsZone.hh"

// c sys headers

// cpp stdlib headers
#include <algorithm>
#include <cctype>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

// 3rd party headers

// project headers

namespace NodeMonitor
{

    namespace
    {

        // dns names are case-insensitive on the wire; we lowercase everything before comparing
        std::string to_lower(const std::string& s)
        {

            std::string out { };
            out.reserve(s.size());
            for (char c : s) out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
            return out;

        }

        // strip a trailing dot ("collector.node-monitor.local." -> "collector.node-monitor.local") so we
        // can compare zone membership without worrying about absolute-name shape
        std::string normalize(const std::string& s)
        {

            std::string out { to_lower(s) };
            if (!out.empty() && out.back() == '.') out.pop_back();
            return out;

        }

    }

    DnsZone::DnsZone(const std::string& suffix)
        : m_suffix { normalize(suffix) }
    {

    }

    void DnsZone::bind(const std::string& short_name, std::uint32_t ip, const std::string& source)
    {

        std::string fqdn { to_lower(short_name) + "." + m_suffix };

        std::lock_guard<std::mutex> lock { m_mutex };

        // a stale forward entry from a *different* fqdn may already point at this ip (eg dhcp handed the
        // same ip to a new device after a lease expired). drop that forward + source entry so we don't
        // leave a dangling name pointing at the new owner's ip
        auto stale_owner { m_reverse.find(ip) };
        if (stale_owner != m_reverse.end() && stale_owner->second != fqdn)
        {
            m_forward.erase(stale_owner->second);
            m_sources.erase(stale_owner->second);
        }

        // if this fqdn used to point at a different ip, clear the old reverse entry too
        auto existing_ip { m_forward.find(fqdn) };
        if (existing_ip != m_forward.end() && existing_ip->second != ip) m_reverse.erase(existing_ip->second);

        m_forward[fqdn] = ip;
        m_reverse[ip] = fqdn;
        m_sources[fqdn] = source;

    }

    void DnsZone::unbind(const std::string& short_name)
    {

        std::string fqdn { to_lower(short_name) + "." + m_suffix };

        std::lock_guard<std::mutex> lock { m_mutex };
        auto it { m_forward.find(fqdn) };
        if (it == m_forward.end()) return;

        m_reverse.erase(it->second);
        m_forward.erase(it);
        m_sources.erase(fqdn);

    }

    std::optional<std::uint32_t> DnsZone::lookup_a(const std::string& fqdn) const
    {

        std::string key { normalize(fqdn) };

        std::lock_guard<std::mutex> lock { m_mutex };
        auto it { m_forward.find(key) };
        if (it == m_forward.end()) return std::nullopt;
        return it->second;

    }

    std::optional<std::vector<std::uint8_t>> DnsZone::lookup_aaaa(const std::string& fqdn) const
    {

        auto ip { lookup_a(fqdn) };
        if (!ip.has_value()) return std::nullopt;

        // IPv4-mapped IPv6 layout: 80 bits of zero, 16 bits of 0xFF, then the 32-bit IPv4 address
        std::vector<std::uint8_t> rdata { };
        rdata.reserve(16uz);
        for (std::size_t i { 0uz }; i < 10uz; ++i) rdata.push_back(0u);
        rdata.push_back(0xFFu);
        rdata.push_back(0xFFu);
        rdata.push_back(static_cast<std::uint8_t>((*ip >> 24) & 0xFFu));
        rdata.push_back(static_cast<std::uint8_t>((*ip >> 16) & 0xFFu));
        rdata.push_back(static_cast<std::uint8_t>((*ip >> 8) & 0xFFu));
        rdata.push_back(static_cast<std::uint8_t>(*ip & 0xFFu));
        return rdata;

    }

    std::optional<std::string> DnsZone::lookup_ptr(const std::string& arpa_name) const
    {

        // arpa form for ipv4: "<d>.<c>.<b>.<a>.in-addr.arpa" -> a.b.c.d
        std::string key { normalize(arpa_name) };
        const std::string suffix { ".in-addr.arpa" };
        if (key.size() <= suffix.size() || key.compare(key.size() - suffix.size(), suffix.size(), suffix) != 0) return std::nullopt;

        std::string nums { key.substr(0uz, key.size() - suffix.size()) };

        // split nums on '.' into 4 octets; bail on any malformed component
        std::uint32_t parts[4] { 0u, 0u, 0u, 0u };
        std::size_t idx { 0uz };
        std::size_t start { 0uz };
        for (std::size_t i { 0uz }; i <= nums.size(); ++i)
        {
            if (i == nums.size() || nums[i] == '.')
            {
                if (idx > 3uz) return std::nullopt;
                if (i == start) return std::nullopt;
                std::uint32_t v { 0u };
                for (std::size_t j { start }; j < i; ++j)
                {
                    if (nums[j] < '0' || nums[j] > '9') return std::nullopt;
                    v = v * 10u + static_cast<std::uint32_t>(nums[j] - '0');
                }
                if (v > 255u) return std::nullopt;
                parts[idx] = v;
                ++idx;
                start = i + 1uz;
            }
        }
        if (idx != 4uz) return std::nullopt;

        // reverse: arpa is least-significant-first; ip should be a.b.c.d
        std::uint32_t ip { (parts[3] << 24) | (parts[2] << 16) | (parts[1] << 8) | parts[0] };

        std::lock_guard<std::mutex> lock { m_mutex };
        auto it { m_reverse.find(ip) };
        if (it == m_reverse.end()) return std::nullopt;
        return it->second;

    }

    bool DnsZone::covers(const std::string& fqdn) const
    {

        std::string key { normalize(fqdn) };

        // any in-addr.arpa name belongs to us for reverse lookups
        const std::string arpa_suffix { ".in-addr.arpa" };
        if (key.size() > arpa_suffix.size() && key.compare(key.size() - arpa_suffix.size(), arpa_suffix.size(), arpa_suffix) == 0) return true;

        if (key == m_suffix) return true;
        std::string dotted { "." + m_suffix };
        if (key.size() <= dotted.size()) return false;
        return key.compare(key.size() - dotted.size(), dotted.size(), dotted) == 0;

    }

    const std::string& DnsZone::suffix() const noexcept
    {

        return m_suffix;

    }

    std::vector<DnsZoneEntry> DnsZone::snapshot() const
    {

        std::vector<DnsZoneEntry> out { };
        std::lock_guard<std::mutex> lock { m_mutex };
        out.reserve(m_forward.size());
        for (const auto& [fqdn, ip] : m_forward)
        {
            DnsZoneEntry e { };
            e.m_fqdn = fqdn;
            e.m_ip = ip;
            auto src_it { m_sources.find(fqdn) };
            e.m_source = src_it != m_sources.end() ? src_it->second : std::string { "unknown" };
            out.push_back(std::move(e));
        }
        return out;

    }

    std::size_t DnsZone::entry_count() const
    {

        std::lock_guard<std::mutex> lock { m_mutex };
        return m_forward.size();

    }

}
