// related headers
#include "SnmpMessage.hh"

// c sys headers

// cpp stdlib headers
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <variant>
#include <vector>

// 3rd party headers

// project headers

namespace NodeMonitor
{

    namespace
    {

        // serialize one varbind: SEQUENCE { name OID, value <typed> }. exception markers carry no body
        std::vector<std::uint8_t> encode_varbind(const SnmpVarbind& vb)
        {

            std::vector<std::uint8_t> body { };

            // OID name
            auto name { AsnBer::encode_oid(vb.m_oid) };
            body.insert(body.end(), name.begin(), name.end());

            // typed value
            switch (vb.m_value_tag)
            {

                case AsnBer::k_tag_null:
                {
                    auto v { AsnBer::encode_null() };
                    body.insert(body.end(), v.begin(), v.end());
                    break;
                }
                case AsnBer::k_tag_integer:
                {
                    std::int64_t x { std::holds_alternative<std::int64_t>(vb.m_value) ? std::get<std::int64_t>(vb.m_value) : 0 };
                    auto v { AsnBer::encode_integer(x) };
                    body.insert(body.end(), v.begin(), v.end());
                    break;
                }
                case AsnBer::k_tag_octet_string:
                {
                    const std::string& s { std::holds_alternative<std::string>(vb.m_value) ? std::get<std::string>(vb.m_value) : std::string { } };
                    auto v { AsnBer::encode_octet_string(s) };
                    body.insert(body.end(), v.begin(), v.end());
                    break;
                }
                case AsnBer::k_tag_oid:
                {
                    const AsnBer::Oid& o { std::holds_alternative<AsnBer::Oid>(vb.m_value) ? std::get<AsnBer::Oid>(vb.m_value) : AsnBer::Oid { } };
                    auto v { AsnBer::encode_oid(o) };
                    body.insert(body.end(), v.begin(), v.end());
                    break;
                }
                case AsnBer::k_tag_counter32:
                {
                    std::uint32_t x { std::holds_alternative<std::uint32_t>(vb.m_value) ? std::get<std::uint32_t>(vb.m_value) : 0u };
                    auto v { AsnBer::encode_counter32(x) };
                    body.insert(body.end(), v.begin(), v.end());
                    break;
                }
                case AsnBer::k_tag_gauge32:
                {
                    std::uint32_t x { std::holds_alternative<std::uint32_t>(vb.m_value) ? std::get<std::uint32_t>(vb.m_value) : 0u };
                    auto v { AsnBer::encode_gauge32(x) };
                    body.insert(body.end(), v.begin(), v.end());
                    break;
                }
                case AsnBer::k_tag_time_ticks:
                {
                    std::uint32_t x { std::holds_alternative<std::uint32_t>(vb.m_value) ? std::get<std::uint32_t>(vb.m_value) : 0u };
                    auto v { AsnBer::encode_time_ticks(x) };
                    body.insert(body.end(), v.begin(), v.end());
                    break;
                }
                case AsnBer::k_tag_no_such_object:
                case AsnBer::k_tag_no_such_instance:
                case AsnBer::k_tag_end_of_mib_view:
                {
                    // exception markers are encoded as a context-specific primitive with zero-length value
                    body.push_back(vb.m_value_tag);
                    body.push_back(0u);
                    break;
                }
                default:
                {
                    // unknown value type; emit NULL so the message stays valid
                    auto v { AsnBer::encode_null() };
                    body.insert(body.end(), v.begin(), v.end());
                    break;
                }

            }

            return AsnBer::encode_sequence(body);

        }

        // parse one SEQUENCE-wrapped varbind from the given offset; advances out_consumed
        std::optional<SnmpVarbind> parse_varbind(const std::uint8_t* data, std::size_t len, std::size_t offset, std::size_t& out_consumed)
        {

            auto tlv { AsnBer::parse_tlv(data, len, offset) };
            if (!tlv.has_value() || tlv->m_tag != AsnBer::k_tag_sequence) return std::nullopt;
            out_consumed = tlv->m_total_size;

            std::size_t inner_off { tlv->m_value_offset };
            std::size_t inner_end { tlv->m_value_offset + tlv->m_value_length };

            // name
            auto name_tlv { AsnBer::parse_tlv(data, inner_end, inner_off) };
            if (!name_tlv.has_value() || name_tlv->m_tag != AsnBer::k_tag_oid) return std::nullopt;
            auto name { AsnBer::parse_oid_value(data, inner_end, name_tlv->m_value_offset, name_tlv->m_value_length) };
            if (!name.has_value()) return std::nullopt;
            inner_off += name_tlv->m_total_size;

            // value
            auto val_tlv { AsnBer::parse_tlv(data, inner_end, inner_off) };
            if (!val_tlv.has_value()) return std::nullopt;

            SnmpVarbind vb { };
            vb.m_oid = std::move(*name);
            vb.m_value_tag = val_tlv->m_tag;

            switch (val_tlv->m_tag)
            {

                case AsnBer::k_tag_null:
                case AsnBer::k_tag_no_such_object:
                case AsnBer::k_tag_no_such_instance:
                case AsnBer::k_tag_end_of_mib_view:
                    vb.m_value = std::monostate { };
                    break;
                case AsnBer::k_tag_integer:
                {
                    auto v { AsnBer::parse_integer_value(data, inner_end, val_tlv->m_value_offset, val_tlv->m_value_length) };
                    if (!v.has_value()) return std::nullopt;
                    vb.m_value = *v;
                    break;
                }
                case AsnBer::k_tag_octet_string:
                {
                    auto v { AsnBer::parse_octet_string_value(data, inner_end, val_tlv->m_value_offset, val_tlv->m_value_length) };
                    if (!v.has_value()) return std::nullopt;
                    vb.m_value = std::move(*v);
                    break;
                }
                case AsnBer::k_tag_oid:
                {
                    auto v { AsnBer::parse_oid_value(data, inner_end, val_tlv->m_value_offset, val_tlv->m_value_length) };
                    if (!v.has_value()) return std::nullopt;
                    vb.m_value = std::move(*v);
                    break;
                }
                case AsnBer::k_tag_counter32:
                case AsnBer::k_tag_gauge32:
                case AsnBer::k_tag_time_ticks:
                case AsnBer::k_tag_ip_address:
                {
                    auto v { AsnBer::parse_uint32_value(data, inner_end, val_tlv->m_value_offset, val_tlv->m_value_length) };
                    if (!v.has_value()) return std::nullopt;
                    vb.m_value = *v;
                    break;
                }
                case AsnBer::k_tag_counter64:
                {
                    auto v { AsnBer::parse_uint64_value(data, inner_end, val_tlv->m_value_offset, val_tlv->m_value_length) };
                    if (!v.has_value()) return std::nullopt;
                    vb.m_value = *v;
                    break;
                }
                default:
                    // unknown; preserve the tag but no decoded value
                    vb.m_value = std::monostate { };
                    break;

            }

            return vb;

        }

    }

    std::vector<std::uint8_t> encode_snmp(const SnmpMessage& msg)
    {

        // version + community + PDU all live inside the outer SEQUENCE
        std::vector<std::uint8_t> body { };

        auto version { AsnBer::encode_integer(msg.m_version) };
        body.insert(body.end(), version.begin(), version.end());

        auto community { AsnBer::encode_octet_string(msg.m_community) };
        body.insert(body.end(), community.begin(), community.end());

        // PDU contents: request-id, error-status, error-index, varbinds SEQUENCE
        std::vector<std::uint8_t> pdu_body { };

        auto rid { AsnBer::encode_integer(msg.m_pdu.m_request_id) };
        pdu_body.insert(pdu_body.end(), rid.begin(), rid.end());

        auto es { AsnBer::encode_integer(msg.m_pdu.m_error_status) };
        pdu_body.insert(pdu_body.end(), es.begin(), es.end());

        auto ei { AsnBer::encode_integer(msg.m_pdu.m_error_index) };
        pdu_body.insert(pdu_body.end(), ei.begin(), ei.end());

        std::vector<std::uint8_t> vbs_body { };
        for (const auto& vb : msg.m_pdu.m_varbinds)
        {
            auto enc { encode_varbind(vb) };
            vbs_body.insert(vbs_body.end(), enc.begin(), enc.end());
        }
        auto vbs { AsnBer::encode_sequence(vbs_body) };
        pdu_body.insert(pdu_body.end(), vbs.begin(), vbs.end());

        // wrap the PDU body with its PDU-specific tag (GetRequest / Response / etc.)
        auto pdu { AsnBer::encode_tlv(msg.m_pdu.m_pdu_tag, pdu_body) };
        body.insert(body.end(), pdu.begin(), pdu.end());

        return AsnBer::encode_sequence(body);

    }

    std::optional<SnmpMessage> decode_snmp(const std::uint8_t* data, std::size_t len)
    {

        // outer SEQUENCE
        auto outer { AsnBer::parse_tlv(data, len, 0uz) };
        if (!outer.has_value() || outer->m_tag != AsnBer::k_tag_sequence) return std::nullopt;

        std::size_t pos { outer->m_value_offset };
        std::size_t end { outer->m_value_offset + outer->m_value_length };

        SnmpMessage msg { };

        // version INTEGER
        auto ver_tlv { AsnBer::parse_tlv(data, end, pos) };
        if (!ver_tlv.has_value() || ver_tlv->m_tag != AsnBer::k_tag_integer) return std::nullopt;
        auto ver { AsnBer::parse_integer_value(data, end, ver_tlv->m_value_offset, ver_tlv->m_value_length) };
        if (!ver.has_value()) return std::nullopt;
        msg.m_version = static_cast<std::int32_t>(*ver);
        pos += ver_tlv->m_total_size;

        // community OCTET STRING
        auto com_tlv { AsnBer::parse_tlv(data, end, pos) };
        if (!com_tlv.has_value() || com_tlv->m_tag != AsnBer::k_tag_octet_string) return std::nullopt;
        auto com { AsnBer::parse_octet_string_value(data, end, com_tlv->m_value_offset, com_tlv->m_value_length) };
        if (!com.has_value()) return std::nullopt;
        msg.m_community = std::move(*com);
        pos += com_tlv->m_total_size;

        // PDU (tag is one of GetRequest / GetNextRequest / Response / GetBulkRequest etc.)
        auto pdu_tlv { AsnBer::parse_tlv(data, end, pos) };
        if (!pdu_tlv.has_value()) return std::nullopt;
        msg.m_pdu.m_pdu_tag = pdu_tlv->m_tag;

        std::size_t p_pos { pdu_tlv->m_value_offset };
        std::size_t p_end { pdu_tlv->m_value_offset + pdu_tlv->m_value_length };

        // request-id INTEGER
        auto rid_tlv { AsnBer::parse_tlv(data, p_end, p_pos) };
        if (!rid_tlv.has_value() || rid_tlv->m_tag != AsnBer::k_tag_integer) return std::nullopt;
        auto rid { AsnBer::parse_integer_value(data, p_end, rid_tlv->m_value_offset, rid_tlv->m_value_length) };
        if (!rid.has_value()) return std::nullopt;
        msg.m_pdu.m_request_id = static_cast<std::int32_t>(*rid);
        p_pos += rid_tlv->m_total_size;

        // error-status INTEGER
        auto es_tlv { AsnBer::parse_tlv(data, p_end, p_pos) };
        if (!es_tlv.has_value() || es_tlv->m_tag != AsnBer::k_tag_integer) return std::nullopt;
        auto es { AsnBer::parse_integer_value(data, p_end, es_tlv->m_value_offset, es_tlv->m_value_length) };
        if (!es.has_value()) return std::nullopt;
        msg.m_pdu.m_error_status = static_cast<std::int32_t>(*es);
        p_pos += es_tlv->m_total_size;

        // error-index INTEGER
        auto ei_tlv { AsnBer::parse_tlv(data, p_end, p_pos) };
        if (!ei_tlv.has_value() || ei_tlv->m_tag != AsnBer::k_tag_integer) return std::nullopt;
        auto ei { AsnBer::parse_integer_value(data, p_end, ei_tlv->m_value_offset, ei_tlv->m_value_length) };
        if (!ei.has_value()) return std::nullopt;
        msg.m_pdu.m_error_index = static_cast<std::int32_t>(*ei);
        p_pos += ei_tlv->m_total_size;

        // varbinds SEQUENCE OF SEQUENCE
        auto vbs_tlv { AsnBer::parse_tlv(data, p_end, p_pos) };
        if (!vbs_tlv.has_value() || vbs_tlv->m_tag != AsnBer::k_tag_sequence) return std::nullopt;

        std::size_t vb_pos { vbs_tlv->m_value_offset };
        std::size_t vb_end { vbs_tlv->m_value_offset + vbs_tlv->m_value_length };
        while (vb_pos < vb_end)
        {
            std::size_t consumed { 0uz };
            auto vb { parse_varbind(data, vb_end, vb_pos, consumed) };
            if (!vb.has_value()) return std::nullopt;
            msg.m_pdu.m_varbinds.push_back(std::move(*vb));
            vb_pos += consumed;
        }

        return msg;

    }

}
