#ifndef NODE_MONITOR_DHCP_PACKET_HH
#define NODE_MONITOR_DHCP_PACKET_HH

// related headers

// c sys headers

// cpp stdlib headers
#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

// 3rd party headers

// project headers

namespace NodeMonitor
{

    // RFC 2131 message types carried in option 53. covers the four DORA messages, the release path, and
    // the negative ack ("you can't have that ip"); decline / inform are spec-required but we don't emit them
    enum class DhcpMessageType : std::uint8_t
    {

        Discover = 1, // client: "any server out there with an ip for me?"
        Offer    = 2, // server: "yes; here's a proposal"
        Request  = 3, // client: "accepted; binding this ip please"
        Decline  = 4, // client: "the ip you offered conflicts; never give it out again"
        Ack      = 5, // server: "confirmed; the ip is yours for the lease duration"
        Nak      = 6, // server: "request rejected; restart DORA"
        Release  = 7, // client: "i'm done with this ip, free it"
        Inform   = 8, // client: "i have an ip already; just give me config options"

    };

    // option codes we actually read or write. RFC 2132 defines many more; we ignore those during decode
    enum class DhcpOptionCode : std::uint8_t
    {

        Pad            = 0,   // 1-byte filler used to align option boundaries; carries no value
        SubnetMask     = 1,   // client's subnet mask (4 bytes)
        Router         = 3,   // default gateway list (4 bytes per entry, we send one)
        DnsServer      = 6,   // dns server list (4 bytes per entry, we send one)
        Hostname       = 12,  // client-supplied hostname; persisted with the lease for visibility
        RequestedIp    = 50,  // client preference for which ip it wants (4 bytes)
        LeaseTime      = 51,  // lease duration in seconds (4 bytes, big endian)
        MessageType    = 53,  // DhcpMessageType (1 byte)
        ServerId       = 54,  // identifies which server an OFFER / ACK came from (4 bytes)
        ParameterList  = 55,  // client's wish list of options to receive in OFFER / ACK
        RenewalTime    = 58,  // T1 in seconds (4 bytes); typically 50% of lease
        RebindingTime  = 59,  // T2 in seconds (4 bytes); typically 87.5% of lease
        ClientId       = 61,  // client identifier; usually htype + mac
        End            = 255, // terminator; signals "no more options follow"

    };

    // BOOTP magic cookie that immediately follows the fixed-size BOOTP header and signals "options follow"
    constexpr std::uint32_t k_dhcp_magic_cookie { 0x63825363u };

    // BOOTP op-codes; 1 from a client, 2 from a server
    constexpr std::uint8_t k_bootp_request { 1 };
    constexpr std::uint8_t k_bootp_reply   { 2 };

    // ethernet hardware type and address length used in the BOOTP header
    constexpr std::uint8_t k_htype_ethernet { 1 };
    constexpr std::uint8_t k_hlen_ethernet  { 6 };

    // fixed BOOTP header size (236 bytes) + magic cookie (4 bytes) = minimum bytes before options
    constexpr std::size_t k_dhcp_header_size { 236uz };
    constexpr std::size_t k_dhcp_cookie_size { 4uz };
    constexpr std::size_t k_dhcp_min_packet  { k_dhcp_header_size + k_dhcp_cookie_size + 1uz }; // + at least End option

    // decoded representation of a dhcp packet. ip fields are kept in host byte order so the rest of the
    // server code doesn't have to remember to ntohl every time it touches them
    struct DhcpPacket
    {

        std::uint8_t  m_op { 0 };                    // 1 = request from client, 2 = reply from server
        std::uint8_t  m_htype { k_htype_ethernet };  // hardware type; 1 = ethernet
        std::uint8_t  m_hlen { k_hlen_ethernet };    // hardware address length; 6 = ethernet mac
        std::uint8_t  m_hops { 0 };                  // 0 from client; incremented by each relay agent

        std::uint32_t m_xid { 0 };                   // transaction id echoed across all 4 messages in DORA
        std::uint16_t m_secs { 0 };                  // seconds elapsed since client started acquiring an ip
        std::uint16_t m_flags { 0 };                 // bit 15 = broadcast flag; clear bits are reserved

        std::uint32_t m_ciaddr { 0 };                // client ip; set only when already bound (renew / rebind)
        std::uint32_t m_yiaddr { 0 };                // "your" ip; server fills this with the offered/granted ip
        std::uint32_t m_siaddr { 0 };                // next-server ip used for bootp boot; unused here
        std::uint32_t m_giaddr { 0 };                // relay agent ip; set by a router relaying for another subnet

        std::array<std::uint8_t, 16> m_chaddr { };   // client hardware address; mac in first 6 bytes, zeros after
        std::array<std::uint8_t, 64> m_sname { };    // optional server hostname string; we leave it empty
        std::array<std::uint8_t, 128> m_file { };    // optional boot file name; we leave it empty

        // raw options blob preserved as (code, value bytes). order of insertion is the order on the wire,
        // which lets servers honor option 55 (parameter request list) ordering for clients that care
        std::vector<std::pair<std::uint8_t, std::vector<std::uint8_t>>> m_options { };

    };

    // pack the 6-byte ethernet mac sitting in m_chaddr[0..6) into a uint64 for use as a hash-map key
    std::uint64_t mac_pack(const std::array<std::uint8_t, 16>& chaddr) noexcept;

    // unpack the lower 48 bits back into a 6-byte array (upper 16 bits are dropped)
    std::array<std::uint8_t, 6> mac_unpack(std::uint64_t packed) noexcept;

    // format as "aa:bb:cc:dd:ee:ff" for logging and the dashboard
    std::string mac_to_string(std::uint64_t packed);

    // host-byte-order ipv4 -> "10.42.0.7"; mirrors AclRule's existing CidrMatcher formatter but standalone
    std::string ipv4_to_dotted(std::uint32_t addr);

    // pull a single option's value bytes by code; returns nullopt if the option isn't present
    std::optional<std::vector<std::uint8_t>> get_option(const DhcpPacket& pkt, DhcpOptionCode code);

    // convenience extractor for the message type (option 53); nullopt when missing or malformed
    std::optional<DhcpMessageType> get_message_type(const DhcpPacket& pkt);

    // decode a raw wire packet. returns nullopt for any failure: too short, missing magic cookie, malformed
    // option that runs off the end of the buffer, etc. the codec is intentionally strict because malformed
    // dhcp on the wire is the kind of thing we want to log, not silently accept
    std::optional<DhcpPacket> decode_dhcp(const std::uint8_t* data, std::size_t len);

    // serialize a DhcpPacket to bytes. always emits the End option (0xFF) at the tail; pads the options
    // section with zeros if the encoded payload is below the typical 300-byte minimum some clients expect
    std::vector<std::uint8_t> encode_dhcp(const DhcpPacket& packet);

}

#endif // NODE_MONITOR_DHCP_PACKET_HH
