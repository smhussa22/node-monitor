// related headers
#include "AclEngine.hh"
#include "AclRule.hh"

// c sys headers

// cpp stdlib headers
#include <cstdint>
#include <memory>
#include <string>
#include <thread>
#include <vector>

// 3rd party headers
#include <gtest/gtest.h>

// project headers

using namespace NodeMonitor;

// ============================================================
//  CidrMatcher
// ============================================================

// mask 0 is the "any" wildcard — must match every address
TEST(CidrMatcher, AnyMatchesAll)
{

    CidrMatcher any { 0u, 0u, 0u };
    EXPECT_TRUE(any.matches(0u));
    EXPECT_TRUE(any.matches(0xFFFFFFFFu));
    EXPECT_TRUE(any.matches(0x0A2A0001u));

}

// a /32 must match only the exact host address
TEST(CidrMatcher, ExactHost32)
{

    CidrMatcher m { parse_cidr("10.42.0.1") };
    EXPECT_TRUE(m.matches(0x0A2A0001u));
    EXPECT_FALSE(m.matches(0x0A2A0002u));
    EXPECT_FALSE(m.matches(0x0A2A0000u));

}

// a /24 must include addresses in the block and exclude addresses outside
TEST(CidrMatcher, Slash24Boundaries)
{

    CidrMatcher m { parse_cidr("10.42.0.0/24") };
    EXPECT_TRUE(m.matches(0x0A2A0000u));   // network
    EXPECT_TRUE(m.matches(0x0A2A00FFu));   // broadcast
    EXPECT_TRUE(m.matches(0x0A2A007Fu));   // mid-range
    EXPECT_FALSE(m.matches(0x0A2A0100u));  // .1 of next /24
    EXPECT_FALSE(m.matches(0x0B000000u));  // completely different

}

// parse_cidr("any") must produce the wildcard matcher
TEST(CidrMatcher, ParseAny)
{

    CidrMatcher m { parse_cidr("any") };
    EXPECT_EQ(m.m_mask, 0u);
    EXPECT_TRUE(m.matches(0xDEADBEEFu));

}

// parse_cidr with a sloppy host address must canonicalize to the network address
TEST(CidrMatcher, ParseSloppyInput)
{

    CidrMatcher m { parse_cidr("10.1.2.3/8") };
    EXPECT_EQ(m.m_network, 0x0A000000u);

}

// ============================================================
//  PortRange
// ============================================================

// [0, 65535] is the "any" wildcard — every port must match
TEST(PortRange, AnyMatchesAll)
{

    PortRange any { parse_port_range("any") };
    EXPECT_TRUE(any.matches(0u));
    EXPECT_TRUE(any.matches(80u));
    EXPECT_TRUE(any.matches(65535u));

}

// a single-port range must match only that port
TEST(PortRange, SinglePort)
{

    PortRange r { parse_port_range("80") };
    EXPECT_TRUE(r.matches(80u));
    EXPECT_FALSE(r.matches(79u));
    EXPECT_FALSE(r.matches(81u));

}

// a range like "1024-65535" must include both endpoints and exclude outside
TEST(PortRange, PortRangeInclusive)
{

    PortRange r { parse_port_range("1024-65535") };
    EXPECT_TRUE(r.matches(1024u));
    EXPECT_TRUE(r.matches(65535u));
    EXPECT_TRUE(r.matches(8080u));
    EXPECT_FALSE(r.matches(1023u));

}

// parse_protocol must handle all four identifiers case-insensitively
TEST(AclParsers, ParseProtocol)
{

    EXPECT_EQ(parse_protocol("TCP"), AclProtocol::Tcp);
    EXPECT_EQ(parse_protocol("tcp"), AclProtocol::Tcp);
    EXPECT_EQ(parse_protocol("UDP"), AclProtocol::Udp);
    EXPECT_EQ(parse_protocol("ICMP"), AclProtocol::Icmp);
    EXPECT_EQ(parse_protocol("any"), AclProtocol::Any);
    EXPECT_THROW(parse_protocol("SCTP"), std::invalid_argument);

}

// ============================================================
//  AclRule matching
// ============================================================

namespace
{

    // helper to build a concrete AclRule without boilerplate
    std::unique_ptr<AclRule> make_rule(std::uint32_t id, AclAction action, const std::string& src, const std::string& dst, const std::string& sport, const std::string& dport, const std::string& proto)
    {

        return std::make_unique<AclRule>(
            id, action,
            parse_protocol(proto),
            parse_cidr(src), parse_cidr(dst),
            parse_port_range(sport), parse_port_range(dport),
            "test rule"
        );

    }

}

// a fully specified 5-tuple must match when all components align
TEST(AclRule, MatchesFull5Tuple)
{

    auto rule { make_rule(1u, AclAction::Permit, "10.0.0.0/8", "8.8.8.0/24", "any", "53", "UDP") };
    std::uint32_t src { 0x0A000001u };   // 10.0.0.1
    std::uint32_t dst { 0x08080808u };   // 8.8.8.8
    EXPECT_TRUE(rule->matches(src, dst, 54321u, 53u, AclProtocol::Udp));

}

// a rule does not match when the protocol differs
TEST(AclRule, ProtocolMismatch)
{

    auto rule { make_rule(1u, AclAction::Deny, "any", "any", "any", "any", "TCP") };
    EXPECT_FALSE(rule->matches(0u, 0u, 0u, 0u, AclProtocol::Udp));

}

// an ICMP rule must ignore ports (ICMP has no port concept)
TEST(AclRule, IcmpIgnoresPorts)
{

    auto rule { make_rule(1u, AclAction::Permit, "any", "any", "1024-65535", "1-1023", "ICMP") };
    // ports are outside the rule's ranges, but ICMP should match anyway
    EXPECT_TRUE(rule->matches(0u, 0u, 0u, 0u, AclProtocol::Icmp));

}

// record_hit increments the counter; hits() reads it back
TEST(AclRule, HitCounter)
{

    auto rule { make_rule(1u, AclAction::Permit, "any", "any", "any", "any", "any") };
    EXPECT_EQ(rule->hits(), 0u);
    rule->record_hit();
    rule->record_hit();
    EXPECT_EQ(rule->hits(), 2u);

}

// ============================================================
//  AclEngine
// ============================================================

// an engine with no rules must return an implicit deny (rule_id == -1)
TEST(AclEngine, EmptyEngineImplicitDeny)
{

    AclEngine engine { };
    auto verdict { engine.evaluate(0u, 0u, 0u, 0u, AclProtocol::Tcp) };
    EXPECT_EQ(verdict.m_action, AclAction::Deny);
    EXPECT_EQ(verdict.m_rule_id, -1);
    EXPECT_EQ(engine.implicit_denies(), 1u);

}

// a single permit rule must match and return Permit
TEST(AclEngine, SinglePermitRule)
{

    AclEngine engine { };
    engine.register_rule(make_rule(10u, AclAction::Permit, "any", "any", "any", "any", "any"));
    auto verdict { engine.evaluate(0u, 0u, 0u, 0u, AclProtocol::Udp) };
    EXPECT_EQ(verdict.m_action, AclAction::Permit);
    EXPECT_EQ(verdict.m_rule_id, 10);
    EXPECT_EQ(engine.total_permits(), 1u);
    EXPECT_EQ(engine.total_denies(), 0u);

}

// a single deny rule must match and return Deny with the rule ID
TEST(AclEngine, SingleDenyRule)
{

    AclEngine engine { };
    engine.register_rule(make_rule(5u, AclAction::Deny, "any", "any", "any", "any", "any"));
    auto verdict { engine.evaluate(0u, 0u, 0u, 0u, AclProtocol::Tcp) };
    EXPECT_EQ(verdict.m_action, AclAction::Deny);
    EXPECT_EQ(verdict.m_rule_id, 5);
    EXPECT_EQ(engine.total_denies(), 1u);

}

// first-match-wins: a permit before a deny must produce Permit
TEST(AclEngine, FirstMatchWinsPermitBeforeDeny)
{

    AclEngine engine { };
    engine.register_rule(make_rule(1u, AclAction::Permit, "any", "any", "any", "any", "any"));
    engine.register_rule(make_rule(2u, AclAction::Deny, "any", "any", "any", "any", "any"));

    auto verdict { engine.evaluate(0u, 0u, 0u, 0u, AclProtocol::Tcp) };
    EXPECT_EQ(verdict.m_action, AclAction::Permit);
    EXPECT_EQ(verdict.m_rule_id, 1);

}

// first-match-wins: a deny before a permit must produce Deny
TEST(AclEngine, FirstMatchWinsDenyBeforePermit)
{

    AclEngine engine { };
    engine.register_rule(make_rule(1u, AclAction::Deny, "any", "any", "any", "any", "TCP"));
    engine.register_rule(make_rule(2u, AclAction::Permit, "any", "any", "any", "any", "any"));

    // TCP: rule 1 fires
    auto tcp_verdict { engine.evaluate(0u, 0u, 0u, 0u, AclProtocol::Tcp) };
    EXPECT_EQ(tcp_verdict.m_action, AclAction::Deny);
    EXPECT_EQ(tcp_verdict.m_rule_id, 1);

    // UDP: rule 1 doesn't match, rule 2 fires
    auto udp_verdict { engine.evaluate(0u, 0u, 0u, 0u, AclProtocol::Udp) };
    EXPECT_EQ(udp_verdict.m_action, AclAction::Permit);
    EXPECT_EQ(udp_verdict.m_rule_id, 2);

}

// evaluation counters must accumulate correctly across mixed verdicts
TEST(AclEngine, CountersAccumulate)
{

    AclEngine engine { };
    engine.register_rule(make_rule(1u, AclAction::Permit, "10.0.0.0/8", "any", "any", "any", "any"));

    std::uint32_t inside  { 0x0A000001u };  // 10.0.0.1 — matches rule 1
    std::uint32_t outside { 0x0B000001u };  // 11.0.0.1 — falls through to implicit deny

    engine.evaluate(inside, 0u, 0u, 0u, AclProtocol::Tcp);
    engine.evaluate(inside, 0u, 0u, 0u, AclProtocol::Tcp);
    engine.evaluate(outside, 0u, 0u, 0u, AclProtocol::Tcp);

    EXPECT_EQ(engine.total_evaluations(), 3u);
    EXPECT_EQ(engine.total_permits(), 2u);
    EXPECT_EQ(engine.implicit_denies(), 1u);

}

// snapshot must list every registered rule
TEST(AclEngine, SnapshotContainsAllRules)
{

    AclEngine engine { };
    engine.register_rule(make_rule(1u, AclAction::Permit, "any", "any", "any", "80", "TCP"));
    engine.register_rule(make_rule(2u, AclAction::Deny, "any", "any", "any", "any", "any"));

    auto snap { engine.snapshot() };
    ASSERT_EQ(snap.size(), 2uz);
    EXPECT_EQ(snap[0].m_id, 1u);
    EXPECT_EQ(snap[1].m_id, 2u);

}

// concurrent evaluate calls must not data-race (tsan will catch it if not properly locked)
TEST(AclEngine, ThreadSafeConcurrentEvaluate)
{

    AclEngine engine { };
    engine.register_rule(make_rule(1u, AclAction::Permit, "any", "any", "any", "any", "any"));

    constexpr std::size_t k_threads { 8uz };
    constexpr std::size_t k_iterations { 1000uz };
    std::vector<std::thread> threads { };
    threads.reserve(k_threads);

    for (std::size_t t { 0uz }; t < k_threads; ++t)
    {

        threads.emplace_back([&engine]()
        {

            for (std::size_t i { 0uz }; i < k_iterations; ++i)
                engine.evaluate(0u, 0u, 0u, 0u, AclProtocol::Tcp);

        });

    }

    for (auto& t : threads) t.join();

    EXPECT_EQ(engine.total_evaluations(), k_threads * k_iterations);

}
