// related headers

// c sys headers

// cpp stdlib headers
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <optional>
#include <print>
#include <random>
#include <string>
#include <utility>
#include <vector>

// 3rd party headers

// project headers
#include "DhcpPacket.hh"
#include "DhcpPool.hh"

namespace
{

    // generate one synthetic DISCOVER + a matching REQUEST for a unique mac, packed-encoded ready for
    // decode-and-handle. we feed both into the codec + pool + lease map without going through UDP so
    // the measured cost is the protocol + state-machine path itself
    struct SyntheticExchange
    {

        std::vector<std::uint8_t> m_discover { };
        std::vector<std::uint8_t> m_request { };

    };

    // helper: build a DhcpPacket with a given message-type option, optionally a requested-ip option
    ::NodeMonitor::DhcpPacket make_packet(std::uint32_t xid, const std::array<std::uint8_t, 6>& mac, ::NodeMonitor::DhcpMessageType type, std::optional<std::uint32_t> requested_ip)
    {

        using namespace ::NodeMonitor;
        DhcpPacket pkt { };
        pkt.m_op = k_bootp_request;
        pkt.m_htype = k_htype_ethernet;
        pkt.m_hlen = k_hlen_ethernet;
        pkt.m_xid = xid;
        for (std::size_t i { 0uz }; i < 6uz; ++i) pkt.m_chaddr[i] = mac[i];

        // option 53 (message type)
        pkt.m_options.emplace_back(static_cast<std::uint8_t>(DhcpOptionCode::MessageType), std::vector<std::uint8_t> { static_cast<std::uint8_t>(type) });

        // option 50 (requested ip)
        if (requested_ip.has_value())
        {
            std::uint32_t ip { *requested_ip };
            pkt.m_options.emplace_back(static_cast<std::uint8_t>(DhcpOptionCode::RequestedIp), std::vector<std::uint8_t> {
                static_cast<std::uint8_t>((ip >> 24) & 0xFFu),
                static_cast<std::uint8_t>((ip >> 16) & 0xFFu),
                static_cast<std::uint8_t>((ip >> 8) & 0xFFu),
                static_cast<std::uint8_t>(ip & 0xFFu),
            });
        }

        return pkt;

    }

    // walk the options blob from a decoded packet and find option 53 (message type)
    std::optional<::NodeMonitor::DhcpMessageType> read_msg_type(const ::NodeMonitor::DhcpPacket& pkt)
    {

        return ::NodeMonitor::get_message_type(pkt);

    }

    // simulate the in-process DHCP server's response to a DISCOVER + REQUEST pair using just the pool
    // allocator + a tiny lease table; this is what DhcpServer::handle_discover + handle_request do
    // minus the socket and the optional MetricStore / DnsZone callbacks
    struct LeaseEntry
    {

        std::uint32_t m_ip { 0u };
        bool m_bound { false };

    };

    // returns true when the pair turns into a Bound lease; false on pool exhaustion or codec error
    bool exchange(const std::vector<std::uint8_t>& discover_bytes, const std::vector<std::uint8_t>& request_bytes, ::NodeMonitor::DhcpPool& pool, std::vector<LeaseEntry>& leases)
    {

        using namespace ::NodeMonitor;

        // DISCOVER: decode, allocate, build OFFER bytes (so the encode path is in the measurement too)
        auto d_pkt { decode_dhcp(discover_bytes.data(), discover_bytes.size()) };
        if (!d_pkt.has_value()) return false;
        auto d_type { read_msg_type(*d_pkt) };
        if (!d_type.has_value() || *d_type != DhcpMessageType::Discover) return false;

        std::uint32_t offered { pool.allocate(0u) };
        if (offered == 0u) return false;

        DhcpPacket offer { *d_pkt };
        offer.m_op = k_bootp_reply;
        offer.m_yiaddr = offered;
        offer.m_options.clear();
        offer.m_options.emplace_back(static_cast<std::uint8_t>(DhcpOptionCode::MessageType), std::vector<std::uint8_t> { static_cast<std::uint8_t>(DhcpMessageType::Offer) });
        auto offer_bytes { encode_dhcp(offer) };
        (void)offer_bytes; // we don't reuse it but want the encode cost in the measurement

        // REQUEST: decode, flip the lease to Bound, build ACK bytes
        auto r_pkt { decode_dhcp(request_bytes.data(), request_bytes.size()) };
        if (!r_pkt.has_value()) return false;
        auto r_type { read_msg_type(*r_pkt) };
        if (!r_type.has_value() || *r_type != DhcpMessageType::Request) return false;

        LeaseEntry e { };
        e.m_ip = offered;
        e.m_bound = true;
        leases.push_back(e);

        DhcpPacket ack { *r_pkt };
        ack.m_op = k_bootp_reply;
        ack.m_yiaddr = offered;
        ack.m_options.clear();
        ack.m_options.emplace_back(static_cast<std::uint8_t>(DhcpOptionCode::MessageType), std::vector<std::uint8_t> { static_cast<std::uint8_t>(DhcpMessageType::Ack) });
        auto ack_bytes { encode_dhcp(ack) };
        (void)ack_bytes;

        return true;

    }

}

int main(int argc, char** argv)
{

    using namespace ::NodeMonitor;

    std::size_t n_exchanges { 50'000uz };
    if (argc >= 2)
    {
        try { n_exchanges = std::stoull(argv[1]); }
        catch (...) { std::println("usage: dhcp_bench [n_exchanges]"); return 1; }
    }

    std::println("generating {} synthetic DORA exchanges (DISCOVER + REQUEST pairs)", n_exchanges);

    // pre-encode the request packets so the loop measures only the codec + handler cost. each exchange
    // gets a unique mac so the pool is exercised end-to-end (allocate path, not the lease-reuse fast path)
    std::vector<SyntheticExchange> exchanges { };
    exchanges.reserve(n_exchanges);
    std::mt19937 rng { 1337u };
    std::uniform_int_distribution<int> mac_byte { 0, 255 };
    for (std::size_t i { 0uz }; i < n_exchanges; ++i)
    {
        std::array<std::uint8_t, 6> mac { };
        // first byte: locally-administered + unicast (bit 1 on, bit 0 off)
        mac[0] = static_cast<std::uint8_t>((mac_byte(rng) & 0xFE) | 0x02);
        for (std::size_t b { 1uz }; b < 6uz; ++b) mac[b] = static_cast<std::uint8_t>(mac_byte(rng));

        SyntheticExchange ex { };
        std::uint32_t xid { static_cast<std::uint32_t>(rng()) };
        ex.m_discover = encode_dhcp(make_packet(xid, mac, DhcpMessageType::Discover, std::nullopt));
        ex.m_request  = encode_dhcp(make_packet(xid, mac, DhcpMessageType::Request, std::nullopt));
        exchanges.push_back(std::move(ex));
    }

    // /16 pool gives us ~65k usable addresses; for bench runs above that the pool will exhaust and the
    // remaining exchanges count as failures (still measured)
    std::println("constructing DhcpPool 10.42.0.0/16 (~65k addresses)");
    DhcpPool pool { (10u << 24) | (42u << 16), 16u, ((10u << 24) | (42u << 16)) | 1u, ((10u << 24) | (42u << 16)) | 2u, std::chrono::seconds { 3600 } };

    std::vector<LeaseEntry> leases { };
    leases.reserve(n_exchanges);

    // warmup so the encode/decode paths are jit/cache-resident before we measure
    std::println("warmup pass (min(5000, n))");
    std::size_t warm { exchanges.size() < 5000uz ? exchanges.size() : 5000uz };
    DhcpPool warm_pool { (10u << 24) | (42u << 16), 16u, 0u, 0u, std::chrono::seconds { 3600 } };
    std::vector<LeaseEntry> warm_leases { };
    for (std::size_t i { 0uz }; i < warm; ++i)
        exchange(exchanges[i].m_discover, exchanges[i].m_request, warm_pool, warm_leases);

    // main measurement: run every exchange through the codec + pool + lease append
    std::println("running benchmark");
    std::size_t bound { 0uz };
    auto t_start { std::chrono::steady_clock::now() };
    for (const auto& ex : exchanges)
    {
        if (exchange(ex.m_discover, ex.m_request, pool, leases)) ++bound;
    }
    auto t_end { std::chrono::steady_clock::now() };

    double elapsed_sec { std::chrono::duration<double>(t_end - t_start).count() };
    double per_sec { static_cast<double>(n_exchanges) / elapsed_sec };
    double ns_per { (elapsed_sec * 1e9) / static_cast<double>(n_exchanges) };

    std::println("--- results ---");
    std::println("DORA exchanges  : {}", n_exchanges);
    std::println("bound leases    : {}", bound);
    std::println("pool free / total : {} / {}", pool.free_count(), pool.total_count());
    std::println("elapsed         : {:.3f} sec", elapsed_sec);
    std::println("throughput      : {:.0f} leases/sec", per_sec);
    std::println("avg latency     : {:.0f} ns/lease ({:.2f} us/lease)", ns_per, ns_per / 1000.0);
    std::println("note            : in-process (no kernel UDP). real over-the-wire DORA will be 10-30x slower due to syscall + scheduling overhead.");

    return 0;

}
