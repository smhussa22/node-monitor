#ifndef NODE_MONITOR_DHCP_POOL_HH
#define NODE_MONITOR_DHCP_POOL_HH

// related headers

// c sys headers

// cpp stdlib headers
#include <chrono>
#include <cstdint>
#include <deque>
#include <unordered_set>

// 3rd party headers

// project headers

namespace NodeMonitor
{

    // address allocator for a single dhcp scope. owns the free / in-use bookkeeping but does NOT take any
    // internal locks; the DhcpServer holds one mutex around its lease map + pool operations so we don't
    // need two-lock ordering rules. delete copy / move because the free list and in-use set are large
    class DhcpPool
    {

    public:

        DhcpPool() = delete;
        DhcpPool(std::uint32_t network, std::uint8_t prefix_len, std::uint32_t gateway, std::uint32_t dns, std::chrono::seconds lease_duration);
        ~DhcpPool() = default;

        DhcpPool(const DhcpPool&) = delete;
        DhcpPool& operator=(const DhcpPool&) = delete;
        DhcpPool(DhcpPool&&) = delete;
        DhcpPool& operator=(DhcpPool&&) = delete;

        // pick an available ip; honors a non-zero requested ip if it's still free, otherwise hands out the
        // next free one from the front of the queue. returns 0 when the pool is exhausted
        std::uint32_t allocate(std::uint32_t requested_ip);

        // explicitly mark an ip as in-use; used when restoring leases from postgres on startup
        void mark_in_use(std::uint32_t ip);

        // return an ip back to the free list; safe to call on an ip that was never allocated (no-op)
        void release(std::uint32_t ip);

        // network configuration accessors used when building OFFER / ACK option blobs
        std::uint32_t network() const noexcept;
        std::uint32_t subnet_mask() const noexcept;
        std::uint32_t gateway() const noexcept;
        std::uint32_t dns() const noexcept;
        std::chrono::seconds lease_duration() const noexcept;

        std::size_t free_count() const noexcept;
        std::size_t in_use_count() const noexcept;
        std::size_t total_count() const noexcept;

    private:

        std::uint32_t m_network { 0 };                       // network address (e.g. 10.42.0.0)
        std::uint8_t m_prefix_len { 24 };                    // /24, /16, etc.
        std::uint32_t m_mask { 0xFFFFFF00u };                // derived from m_prefix_len
        std::uint32_t m_broadcast { 0 };                     // last address in the network; reserved
        std::uint32_t m_gateway { 0 };                       // default gateway handed out in option 3
        std::uint32_t m_dns { 0 };                           // dns server handed out in option 6
        std::chrono::seconds m_lease_duration { 3600 };      // lease lifetime; T1 / T2 derive from this

        std::deque<std::uint32_t> m_free { };                // free list; ordered by allocation preference
        std::unordered_set<std::uint32_t> m_in_use { };      // O(1) check for "already allocated"

    };

}

#endif // NODE_MONITOR_DHCP_POOL_HH
