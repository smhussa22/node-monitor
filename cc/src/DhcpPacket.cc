// related headers
#include "DhcpPacket.hh"

// c sys headers

// cpp stdlib headers
#include <cstdint>
#include <cstring>
#include <format>
#include <optional>
#include <string>
#include <utility>
#include <vector>

// 3rd party headers

// project headers

namespace NodeMonitor
{

    // tiny byte-order helpers; we avoid <arpa/inet.h>'s ntohl/htonl here so this file doesn't pull
    // a posix header into a pure data-shape translation unit
    namespace
    {

        std::uint16_t read_be16(const std::uint8_t* p) noexcept
        {

            return static_cast<std::uint16_t>((static_cast<std::uint16_t>(p[0]) << 8) | static_cast<std::uint16_t>(p[1]));

        }

        std::uint32_t read_be32(const std::uint8_t* p) noexcept
        {

            return (static_cast<std::uint32_t>(p[0]) << 24)
                 | (static_cast<std::uint32_t>(p[1]) << 16)
                 | (static_cast<std::uint32_t>(p[2]) << 8)
                 |  static_cast<std::uint32_t>(p[3]);

        }

        void write_be16(std::vector<std::uint8_t>& out, std::uint16_t v)
        {

            out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFFu));
            out.push_back(static_cast<std::uint8_t>(v & 0xFFu));

        }

        void write_be32(std::vector<std::uint8_t>& out, std::uint32_t v)
        {

            out.push_back(static_cast<std::uint8_t>((v >> 24) & 0xFFu));
            out.push_back(static_cast<std::uint8_t>((v >> 16) & 0xFFu));
            out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFFu));
            out.push_back(static_cast<std::uint8_t>(v & 0xFFu));

        }

    }

    std::uint64_t mac_pack(const std::array<std::uint8_t, 16>& chaddr) noexcept
    {

        return (static_cast<std::uint64_t>(chaddr[0]) << 40)
             | (static_cast<std::uint64_t>(chaddr[1]) << 32)
             | (static_cast<std::uint64_t>(chaddr[2]) << 24)
             | (static_cast<std::uint64_t>(chaddr[3]) << 16)
             | (static_cast<std::uint64_t>(chaddr[4]) << 8)
             |  static_cast<std::uint64_t>(chaddr[5]);

    }

    std::array<std::uint8_t, 6> mac_unpack(std::uint64_t packed) noexcept
    {

        return {
            static_cast<std::uint8_t>((packed >> 40) & 0xFFu),
            static_cast<std::uint8_t>((packed >> 32) & 0xFFu),
            static_cast<std::uint8_t>((packed >> 24) & 0xFFu),
            static_cast<std::uint8_t>((packed >> 16) & 0xFFu),
            static_cast<std::uint8_t>((packed >> 8) & 0xFFu),
            static_cast<std::uint8_t>(packed & 0xFFu),
        };

    }

    std::string mac_to_string(std::uint64_t packed)
    {

        auto m { mac_unpack(packed) };
        return std::format("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", m[0], m[1], m[2], m[3], m[4], m[5]);

    }

    std::string ipv4_to_dotted(std::uint32_t addr)
    {

        return std::format("{}.{}.{}.{}", (addr >> 24) & 0xFFu, (addr >> 16) & 0xFFu, (addr >> 8) & 0xFFu, addr & 0xFFu);

    }

    std::optional<std::vector<std::uint8_t>> get_option(const DhcpPacket& pkt, DhcpOptionCode code)
    {

        std::uint8_t target { static_cast<std::uint8_t>(code) };
        for (const auto& [opt_code, opt_val] : pkt.m_options)
        {
            if (opt_code == target) return opt_val;
        }
        return std::nullopt;

    }

    std::optional<DhcpMessageType> get_message_type(const DhcpPacket& pkt)
    {

        auto raw { get_option(pkt, DhcpOptionCode::MessageType) };
        if (!raw.has_value() || raw->size() != 1uz) return std::nullopt;
        std::uint8_t v { (*raw)[0] };
        if (v < 1u || v > 8u) return std::nullopt;
        return static_cast<DhcpMessageType>(v);

    }

    std::optional<DhcpPacket> decode_dhcp(const std::uint8_t* data, std::size_t len)
    {

        if (data == nullptr || len < k_dhcp_min_packet) return std::nullopt;

        DhcpPacket pkt { };

        // walk the fixed BOOTP header byte by byte; offsets match RFC 2131 section 2
        pkt.m_op    = data[0];
        pkt.m_htype = data[1];
        pkt.m_hlen  = data[2];
        pkt.m_hops  = data[3];
        pkt.m_xid   = read_be32(data + 4);
        pkt.m_secs  = read_be16(data + 8);
        pkt.m_flags = read_be16(data + 10);
        pkt.m_ciaddr = read_be32(data + 12);
        pkt.m_yiaddr = read_be32(data + 16);
        pkt.m_siaddr = read_be32(data + 20);
        pkt.m_giaddr = read_be32(data + 24);

        std::memcpy(pkt.m_chaddr.data(), data + 28, 16);
        std::memcpy(pkt.m_sname.data(),  data + 44, 64);
        std::memcpy(pkt.m_file.data(),   data + 108, 128);

        // verify the magic cookie; without it this is plain BOOTP and we don't speak that here
        std::uint32_t cookie { read_be32(data + k_dhcp_header_size) };
        if (cookie != k_dhcp_magic_cookie) return std::nullopt;

        // walk the options blob. each option is (code, length, value[length]) except Pad (1 byte) and End
        std::size_t i { k_dhcp_header_size + k_dhcp_cookie_size };
        while (i < len)
        {

            std::uint8_t code { data[i] };
            if (code == static_cast<std::uint8_t>(DhcpOptionCode::Pad))
            {
                ++i;
                continue;
            }
            if (code == static_cast<std::uint8_t>(DhcpOptionCode::End)) break;

            // every non-Pad, non-End option carries an explicit length byte; if we can't read it bail out
            if (i + 1uz >= len) return std::nullopt;
            std::uint8_t opt_len { data[i + 1uz] };
            if (i + 2uz + static_cast<std::size_t>(opt_len) > len) return std::nullopt;

            std::vector<std::uint8_t> value { data + i + 2uz, data + i + 2uz + opt_len };
            pkt.m_options.emplace_back(code, std::move(value));

            i += 2uz + static_cast<std::size_t>(opt_len);

        }

        return pkt;

    }

    std::vector<std::uint8_t> encode_dhcp(const DhcpPacket& packet)
    {

        std::vector<std::uint8_t> out { };
        out.reserve(300uz);

        // fixed BOOTP header
        out.push_back(packet.m_op);
        out.push_back(packet.m_htype);
        out.push_back(packet.m_hlen);
        out.push_back(packet.m_hops);
        write_be32(out, packet.m_xid);
        write_be16(out, packet.m_secs);
        write_be16(out, packet.m_flags);
        write_be32(out, packet.m_ciaddr);
        write_be32(out, packet.m_yiaddr);
        write_be32(out, packet.m_siaddr);
        write_be32(out, packet.m_giaddr);

        out.insert(out.end(), packet.m_chaddr.begin(), packet.m_chaddr.end());
        out.insert(out.end(), packet.m_sname.begin(), packet.m_sname.end());
        out.insert(out.end(), packet.m_file.begin(), packet.m_file.end());

        // magic cookie
        write_be32(out, k_dhcp_magic_cookie);

        // options
        for (const auto& [code, value] : packet.m_options)
        {

            // skip degenerate values that wouldn't fit in a single byte length field; option spec caps at 255
            if (value.size() > 255uz) continue;

            out.push_back(code);
            out.push_back(static_cast<std::uint8_t>(value.size()));
            out.insert(out.end(), value.begin(), value.end());

        }

        // end of options
        out.push_back(static_cast<std::uint8_t>(DhcpOptionCode::End));

        // pad the trailing options area out to a 300-byte minimum payload; some embedded clients
        // assume a fixed-size BOOTP-shaped packet and silently drop anything shorter
        while (out.size() < 300uz) out.push_back(0u);

        return out;

    }

}
