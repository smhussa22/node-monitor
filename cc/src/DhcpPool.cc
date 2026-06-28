// related headers
#include "DhcpPool.hh"

// c sys headers

// cpp stdlib headers
#include <algorithm>
#include <cstdint>
#include <stdexcept>

// 3rd party headers

// project headers

namespace NodeMonitor
{

    DhcpPool::DhcpPool(std::uint32_t network, std::uint8_t prefix_len, std::uint32_t gateway, std::uint32_t dns, std::chrono::seconds lease_duration)
        : m_prefix_len { prefix_len }, m_gateway { gateway }, m_dns { dns }, m_lease_duration { lease_duration }
    {

        // prefix 0 is "any" which makes no sense for a dhcp scope; require a sane subnet so we don't try
        // to allocate from the entire ipv4 space
        if (prefix_len == 0u || prefix_len > 30u) throw std::invalid_argument { "DhcpPool: prefix_len must be in (0, 30]" };

        // compute the canonical network address and broadcast so callers can be sloppy with input
        m_mask = (0xFFFFFFFFu << (32u - prefix_len));
        m_network = network & m_mask;
        m_broadcast = m_network | ~m_mask;

        // seed the free list with every host address in the range, excluding the network address,
        // the broadcast address, and the gateway (if it falls inside the scope)
        for (std::uint32_t ip { m_network + 1u }; ip < m_broadcast; ++ip)
        {

            if (ip == m_gateway) continue;
            m_free.push_back(ip);

        }

    }

    std::uint32_t DhcpPool::allocate(std::uint32_t requested_ip)
    {

        // honor the client's requested ip if it's inside the scope and still free
        if (requested_ip != 0u && (requested_ip & m_mask) == m_network && m_in_use.find(requested_ip) == m_in_use.end())
        {

            auto it { std::find(m_free.begin(), m_free.end(), requested_ip) };
            if (it != m_free.end())
            {

                m_free.erase(it);
                m_in_use.insert(requested_ip);
                return requested_ip;

            }

        }

        // fall back to the next free address; empty deque means pool exhausted
        if (m_free.empty()) return 0u;

        std::uint32_t ip { m_free.front() };
        m_free.pop_front();
        m_in_use.insert(ip);
        return ip;

    }

    void DhcpPool::mark_in_use(std::uint32_t ip)
    {

        if ((ip & m_mask) != m_network) return;
        if (ip == m_network || ip == m_broadcast || ip == m_gateway) return;

        auto it { std::find(m_free.begin(), m_free.end(), ip) };
        if (it != m_free.end()) m_free.erase(it);
        m_in_use.insert(ip);

    }

    void DhcpPool::release(std::uint32_t ip)
    {

        if ((ip & m_mask) != m_network) return;

        auto found { m_in_use.find(ip) };
        if (found == m_in_use.end()) return;

        m_in_use.erase(found);
        m_free.push_back(ip);

    }

    std::uint32_t DhcpPool::network() const noexcept
    {

        return m_network;

    }

    std::uint32_t DhcpPool::subnet_mask() const noexcept
    {

        return m_mask;

    }

    std::uint32_t DhcpPool::gateway() const noexcept
    {

        return m_gateway;

    }

    std::uint32_t DhcpPool::dns() const noexcept
    {

        return m_dns;

    }

    std::chrono::seconds DhcpPool::lease_duration() const noexcept
    {

        return m_lease_duration;

    }

    std::size_t DhcpPool::free_count() const noexcept
    {

        return m_free.size();

    }

    std::size_t DhcpPool::in_use_count() const noexcept
    {

        return m_in_use.size();

    }

    std::size_t DhcpPool::total_count() const noexcept
    {

        return m_free.size() + m_in_use.size();

    }

}
