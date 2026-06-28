// related headers
#include "DnsPacket.hh"

// c sys headers

// cpp stdlib headers
#include <cctype>
#include <cstdint>
#include <format>
#include <optional>
#include <string>
#include <vector>

// 3rd party headers

// project headers

namespace NodeMonitor
{

    namespace
    {

        // big-endian readers / writers; we avoid <arpa/inet.h> here to keep this translation unit posix-free
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

        // decode a wire-format name starting at offset i. handles compression pointers (0xC0 mask) by
        // jumping to the indicated offset; tracks a hop counter so a malicious self-referencing pointer
        // can't loop us. returns the decoded dotted name and writes the END of the on-wire name back to
        // out_end so the caller knows where to resume parsing the next field. returns nullopt on malformed.
        std::optional<std::string> decode_name(const std::uint8_t* data, std::size_t len, std::size_t i, std::size_t& out_end)
        {

            std::string name { };
            std::size_t hops { 0uz };
            std::size_t cursor { i };
            bool jumped { false };
            std::size_t end_of_name { i };

            while (cursor < len)
            {

                std::uint8_t b { data[cursor] };

                // terminator byte
                if (b == 0u)
                {

                    if (!jumped) end_of_name = cursor + 1uz;
                    out_end = end_of_name;
                    return name;

                }

                // compression pointer: top two bits set; next 14 bits are an offset into the packet
                if ((b & 0xC0u) == 0xC0u)
                {

                    if (cursor + 1uz >= len) return std::nullopt;
                    std::uint16_t ptr { static_cast<std::uint16_t>(((static_cast<std::uint16_t>(b) & 0x3Fu) << 8) | data[cursor + 1uz]) };

                    if (!jumped)
                    {
                        end_of_name = cursor + 2uz;
                        jumped = true;
                    }

                    if (ptr >= len) return std::nullopt;

                    cursor = ptr;
                    if (++hops > 16uz) return std::nullopt;
                    continue;

                }

                // a regular label: b is the length, followed by that many name bytes
                if ((b & 0xC0u) != 0u) return std::nullopt; // 0b10 / 0b01 are reserved and invalid here
                std::size_t lbl_len { static_cast<std::size_t>(b) };
                if (cursor + 1uz + lbl_len > len) return std::nullopt;

                if (!name.empty()) name.push_back('.');
                name.append(reinterpret_cast<const char*>(data + cursor + 1uz), lbl_len);
                cursor += 1uz + lbl_len;

            }

            return std::nullopt;

        }

    }

    void set_qr(DnsHeader& h, bool is_response)
    {

        h.m_flags = static_cast<std::uint16_t>((h.m_flags & 0x7FFFu) | (is_response ? 0x8000u : 0u));

    }

    void set_opcode(DnsHeader& h, DnsOpcode op)
    {

        h.m_flags = static_cast<std::uint16_t>((h.m_flags & ~0x7800u) | ((static_cast<std::uint16_t>(op) & 0x0Fu) << 11));

    }

    void set_aa(DnsHeader& h, bool authoritative)
    {

        h.m_flags = static_cast<std::uint16_t>((h.m_flags & ~0x0400u) | (authoritative ? 0x0400u : 0u));

    }

    void set_rd(DnsHeader& h, bool recursion_desired)
    {

        h.m_flags = static_cast<std::uint16_t>((h.m_flags & ~0x0100u) | (recursion_desired ? 0x0100u : 0u));

    }

    void set_ra(DnsHeader& h, bool recursion_available)
    {

        h.m_flags = static_cast<std::uint16_t>((h.m_flags & ~0x0080u) | (recursion_available ? 0x0080u : 0u));

    }

    void set_rcode(DnsHeader& h, DnsRcode rc)
    {

        h.m_flags = static_cast<std::uint16_t>((h.m_flags & ~0x000Fu) | (static_cast<std::uint16_t>(rc) & 0x0Fu));

    }

    bool get_qr(const DnsHeader& h)
    {

        return (h.m_flags & 0x8000u) != 0u;

    }

    DnsOpcode get_opcode(const DnsHeader& h)
    {

        return static_cast<DnsOpcode>((h.m_flags >> 11) & 0x0Fu);

    }

    bool get_rd(const DnsHeader& h)
    {

        return (h.m_flags & 0x0100u) != 0u;

    }

    DnsRcode get_rcode(const DnsHeader& h)
    {

        return static_cast<DnsRcode>(h.m_flags & 0x0Fu);

    }

    std::vector<std::uint8_t> encode_a_rdata(std::uint32_t addr)
    {

        return {
            static_cast<std::uint8_t>((addr >> 24) & 0xFFu),
            static_cast<std::uint8_t>((addr >> 16) & 0xFFu),
            static_cast<std::uint8_t>((addr >> 8) & 0xFFu),
            static_cast<std::uint8_t>(addr & 0xFFu),
        };

    }

    std::uint32_t decode_a_rdata(const std::vector<std::uint8_t>& rdata)
    {

        if (rdata.size() != 4uz) return 0u;
        return (static_cast<std::uint32_t>(rdata[0]) << 24)
             | (static_cast<std::uint32_t>(rdata[1]) << 16)
             | (static_cast<std::uint32_t>(rdata[2]) << 8)
             |  static_cast<std::uint32_t>(rdata[3]);

    }

    std::vector<std::uint8_t> encode_name_uncompressed(const std::string& name)
    {

        std::vector<std::uint8_t> out { };

        // walk the dotted name and emit (length, label-bytes) pairs; a trailing dot is optional
        std::size_t start { 0uz };
        for (std::size_t i { 0uz }; i <= name.size(); ++i)
        {

            if (i == name.size() || name[i] == '.')
            {

                std::size_t lbl_len { i - start };
                if (lbl_len > 63uz) lbl_len = 63uz;
                if (lbl_len > 0uz)
                {
                    out.push_back(static_cast<std::uint8_t>(lbl_len));
                    out.insert(out.end(), name.begin() + start, name.begin() + start + lbl_len);
                }
                start = i + 1uz;

            }

        }

        // root label terminator
        out.push_back(0u);
        return out;

    }

    std::string ipv4_to_arpa(std::uint32_t addr)
    {

        // reverse the octets: 10.42.0.7 -> "7.0.42.10.in-addr.arpa"
        return std::format("{}.{}.{}.{}.in-addr.arpa", addr & 0xFFu, (addr >> 8) & 0xFFu, (addr >> 16) & 0xFFu, (addr >> 24) & 0xFFu);

    }

    std::optional<DnsPacket> decode_dns(const std::uint8_t* data, std::size_t len)
    {

        if (data == nullptr || len < 12uz) return std::nullopt;

        DnsPacket pkt { };
        pkt.m_header.m_id      = read_be16(data + 0);
        pkt.m_header.m_flags   = read_be16(data + 2);
        pkt.m_header.m_qdcount = read_be16(data + 4);
        pkt.m_header.m_ancount = read_be16(data + 6);
        pkt.m_header.m_nscount = read_be16(data + 8);
        pkt.m_header.m_arcount = read_be16(data + 10);

        std::size_t i { 12uz };

        // questions
        for (std::size_t q { 0uz }; q < pkt.m_header.m_qdcount; ++q)
        {

            std::size_t end { 0uz };
            auto name { decode_name(data, len, i, end) };
            if (!name.has_value()) return std::nullopt;
            i = end;
            if (i + 4uz > len) return std::nullopt;

            DnsQuestion question { };
            question.m_name = std::move(*name);
            question.m_qtype = static_cast<DnsType>(read_be16(data + i));
            question.m_qclass = static_cast<DnsClass>(read_be16(data + i + 2));
            i += 4uz;
            pkt.m_questions.push_back(std::move(question));

        }

        // helper to decode one RR; reused for answers, authority, additional
        auto decode_rr = [&](std::vector<DnsRR>& out_section, std::uint16_t count) -> bool
        {

            for (std::size_t r { 0uz }; r < count; ++r)
            {

                std::size_t end { 0uz };
                auto name { decode_name(data, len, i, end) };
                if (!name.has_value()) return false;
                i = end;
                if (i + 10uz > len) return false;

                DnsRR rr { };
                rr.m_name = std::move(*name);
                rr.m_type = static_cast<DnsType>(read_be16(data + i));
                rr.m_class = static_cast<DnsClass>(read_be16(data + i + 2));
                rr.m_ttl = read_be32(data + i + 4);
                std::uint16_t rdlen { read_be16(data + i + 8) };
                i += 10uz;

                if (i + rdlen > len) return false;
                rr.m_rdata.assign(data + i, data + i + rdlen);
                i += rdlen;

                out_section.push_back(std::move(rr));

            }
            return true;

        };

        if (!decode_rr(pkt.m_answers,    pkt.m_header.m_ancount)) return std::nullopt;
        if (!decode_rr(pkt.m_authority,  pkt.m_header.m_nscount)) return std::nullopt;
        if (!decode_rr(pkt.m_additional, pkt.m_header.m_arcount)) return std::nullopt;

        return pkt;

    }

    std::vector<std::uint8_t> encode_dns(const DnsPacket& packet)
    {

        std::vector<std::uint8_t> out { };
        out.reserve(512uz);

        // header
        write_be16(out, packet.m_header.m_id);
        write_be16(out, packet.m_header.m_flags);
        write_be16(out, static_cast<std::uint16_t>(packet.m_questions.size()));
        write_be16(out, static_cast<std::uint16_t>(packet.m_answers.size()));
        write_be16(out, static_cast<std::uint16_t>(packet.m_authority.size()));
        write_be16(out, static_cast<std::uint16_t>(packet.m_additional.size()));

        // questions
        for (const auto& q : packet.m_questions)
        {

            auto name_bytes { encode_name_uncompressed(q.m_name) };
            out.insert(out.end(), name_bytes.begin(), name_bytes.end());
            write_be16(out, static_cast<std::uint16_t>(q.m_qtype));
            write_be16(out, static_cast<std::uint16_t>(q.m_qclass));

        }

        // RR sections share encoding; small lambda saves repetition
        auto write_rr_section = [&](const std::vector<DnsRR>& section)
        {

            for (const auto& rr : section)
            {

                auto name_bytes { encode_name_uncompressed(rr.m_name) };
                out.insert(out.end(), name_bytes.begin(), name_bytes.end());
                write_be16(out, static_cast<std::uint16_t>(rr.m_type));
                write_be16(out, static_cast<std::uint16_t>(rr.m_class));
                write_be32(out, rr.m_ttl);
                write_be16(out, static_cast<std::uint16_t>(rr.m_rdata.size()));
                out.insert(out.end(), rr.m_rdata.begin(), rr.m_rdata.end());

            }

        };

        write_rr_section(packet.m_answers);
        write_rr_section(packet.m_authority);
        write_rr_section(packet.m_additional);

        return out;

    }

}
