#include <array>
#include <cstdint>
#include <functional>

#include "TestSupport.h"
#include "core/domain/ConnectionKey.h"
#include "core/domain/NonTerminalIpContext.h"

namespace pfl::tests {

namespace {

constexpr std::uint32_t ip4(
    const std::uint32_t a,
    const std::uint32_t b,
    const std::uint32_t c,
    const std::uint32_t d
) noexcept {
    return ((a & 0xffU) << 24U) |
           ((b & 0xffU) << 16U) |
           ((c & 0xffU) << 8U) |
           (d & 0xffU);
}

constexpr std::array<std::uint8_t, 16> ip6(const std::uint8_t suffix) noexcept {
    return std::array<std::uint8_t, 16> {
        0x20, 0x01, 0x0d, 0xb8,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, suffix,
    };
}

EndpointKeyV4 endpoint4(const std::uint32_t address, const std::uint32_t port) noexcept {
    return EndpointKeyV4 {
        .addr = address,
        .port = static_cast<std::uint16_t>(port),
    };
}

EndpointKeyV6 endpoint6(const std::array<std::uint8_t, 16>& address, const std::uint32_t port) noexcept {
    return EndpointKeyV6 {
        .addr = address,
        .port = static_cast<std::uint16_t>(port),
    };
}

NonTerminalIpContext canonicalize_ipv4(
    const NonTerminalIpContextBuilder& builder,
    const std::uint32_t source_address,
    const std::uint32_t source_port,
    const std::uint32_t destination_address,
    const std::uint32_t destination_port
) {
    PFL_REQUIRE(!builder.overflowed());
    return canonicalize_non_terminal_ip_context(
        builder.view(),
        endpoint4(source_address, source_port),
        endpoint4(destination_address, destination_port)
    );
}

NonTerminalIpContext canonicalize_ipv6(
    const NonTerminalIpContextBuilder& builder,
    const std::array<std::uint8_t, 16>& source_address,
    const std::uint32_t source_port,
    const std::array<std::uint8_t, 16>& destination_address,
    const std::uint32_t destination_port
) {
    PFL_REQUIRE(!builder.overflowed());
    return canonicalize_non_terminal_ip_context(
        builder.view(),
        endpoint6(source_address, source_port),
        endpoint6(destination_address, destination_port)
    );
}

void expect_empty_context_uses_reserved_id() {
    NonTerminalIpContextBuilder builder {};
    PFL_EXPECT(builder.empty());
    PFL_EXPECT(!builder.overflowed());

    const auto context = builder.to_context();
    PFL_REQUIRE(context.has_value());
    PFL_EXPECT(context->empty());

    NonTerminalIpContextRegistry registry {};
    const auto id = registry.intern(*context);
    PFL_EXPECT(id == kEmptyNonTerminalIpContextId);
    PFL_EXPECT(registry.size() == 0U);
    PFL_EXPECT(registry.find(kEmptyNonTerminalIpContextId) == nullptr);
}

void expect_basic_ipv4_context_interns_once() {
    NonTerminalIpContextRegistry registry {};
    NonTerminalIpContextBuilder builder {};
    PFL_REQUIRE(builder.push_ipv4(ip4(203, 0, 113, 1), ip4(203, 0, 113, 2)));

    const auto context = builder.to_context();
    PFL_REQUIRE(context.has_value());

    const auto first_id = registry.intern(*context);
    const auto second_id = registry.intern(*context);
    PFL_EXPECT(first_id != kEmptyNonTerminalIpContextId);
    PFL_EXPECT(second_id == first_id);
    PFL_EXPECT(registry.size() == 1U);
}

void expect_basic_ipv6_context_interns_once() {
    NonTerminalIpContextRegistry registry {};
    NonTerminalIpContextBuilder builder {};
    PFL_REQUIRE(builder.push_ipv6(ip6(1), ip6(2)));

    const auto context = builder.to_context();
    PFL_REQUIRE(context.has_value());

    const auto first_id = registry.intern(*context);
    const auto second_id = registry.intern(*context);
    PFL_EXPECT(first_id != kEmptyNonTerminalIpContextId);
    PFL_EXPECT(second_id == first_id);
    PFL_EXPECT(registry.size() == 1U);
}

void expect_mixed_nested_context_retains_order_and_family() {
    NonTerminalIpContextBuilder builder {};
    PFL_REQUIRE(builder.push_ipv4(ip4(198, 51, 100, 1), ip4(198, 51, 100, 2)));
    PFL_REQUIRE(builder.push_ipv6(ip6(10), ip6(20)));

    const auto context = builder.to_context();
    PFL_REQUIRE(context.has_value());
    PFL_REQUIRE(context->size() == 2U);
    PFL_EXPECT((*context)[0] == NonTerminalIpLevel::ipv4(ip4(198, 51, 100, 1), ip4(198, 51, 100, 2)));
    PFL_EXPECT((*context)[1] == NonTerminalIpLevel::ipv6(ip6(10), ip6(20)));
}

void expect_distinct_addresses_level_counts_and_order_remain_distinct() {
    NonTerminalIpContextRegistry registry {};
    const NonTerminalIpContext level_a {
        NonTerminalIpLevel::ipv4(ip4(192, 0, 2, 1), ip4(192, 0, 2, 2)),
    };
    const NonTerminalIpContext level_b {
        NonTerminalIpLevel::ipv4(ip4(192, 0, 2, 3), ip4(192, 0, 2, 4)),
    };
    const NonTerminalIpContext a_then_b {
        NonTerminalIpLevel::ipv4(ip4(192, 0, 2, 1), ip4(192, 0, 2, 2)),
        NonTerminalIpLevel::ipv4(ip4(192, 0, 2, 3), ip4(192, 0, 2, 4)),
    };
    const NonTerminalIpContext b_then_a {
        NonTerminalIpLevel::ipv4(ip4(192, 0, 2, 3), ip4(192, 0, 2, 4)),
        NonTerminalIpLevel::ipv4(ip4(192, 0, 2, 1), ip4(192, 0, 2, 2)),
    };

    PFL_EXPECT(level_a != level_b);
    PFL_EXPECT(level_a != a_then_b);
    PFL_EXPECT(a_then_b != b_then_a);

    const auto id_a = registry.intern(level_a);
    const auto id_b = registry.intern(level_b);
    const auto id_a_then_b = registry.intern(a_then_b);
    const auto id_b_then_a = registry.intern(b_then_a);

    PFL_EXPECT(id_a != id_b);
    PFL_EXPECT(id_a != id_a_then_b);
    PFL_EXPECT(id_a_then_b != id_b_then_a);
}

void expect_forward_reverse_ipv4_canonicalization_matches() {
    NonTerminalIpContextBuilder forward {};
    PFL_REQUIRE(forward.push_ipv4(ip4(203, 0, 113, 10), ip4(203, 0, 113, 20)));
    PFL_REQUIRE(forward.push_ipv4(ip4(198, 51, 100, 10), ip4(198, 51, 100, 20)));

    NonTerminalIpContextBuilder reverse {};
    PFL_REQUIRE(reverse.push_ipv4(ip4(203, 0, 113, 20), ip4(203, 0, 113, 10)));
    PFL_REQUIRE(reverse.push_ipv4(ip4(198, 51, 100, 20), ip4(198, 51, 100, 10)));

    const auto forward_context = canonicalize_ipv4(
        forward,
        ip4(10, 0, 0, 1),
        50000U,
        ip4(10, 0, 0, 2),
        443U
    );
    const auto reverse_context = canonicalize_ipv4(
        reverse,
        ip4(10, 0, 0, 2),
        443U,
        ip4(10, 0, 0, 1),
        50000U
    );

    NonTerminalIpContextRegistry registry {};
    PFL_EXPECT(registry.intern(forward_context) == registry.intern(reverse_context));
}

void expect_same_terminal_direction_with_different_carrier_context_splits() {
    NonTerminalIpContextBuilder first {};
    PFL_REQUIRE(first.push_ipv4(ip4(203, 0, 113, 10), ip4(203, 0, 113, 20)));
    NonTerminalIpContextBuilder second {};
    PFL_REQUIRE(second.push_ipv4(ip4(203, 0, 113, 30), ip4(203, 0, 113, 40)));

    const auto first_context = canonicalize_ipv4(first, ip4(10, 0, 0, 1), 50000U, ip4(10, 0, 0, 2), 443U);
    const auto second_context = canonicalize_ipv4(second, ip4(10, 0, 0, 1), 50000U, ip4(10, 0, 0, 2), 443U);

    NonTerminalIpContextRegistry registry {};
    PFL_EXPECT(registry.intern(first_context) != registry.intern(second_context));
}

void expect_equal_terminal_endpoint_tie_case_is_whole_context_canonical() {
    NonTerminalIpContextBuilder observed {};
    PFL_REQUIRE(observed.push_ipv4(ip4(203, 0, 113, 100), ip4(203, 0, 113, 10)));
    PFL_REQUIRE(observed.push_ipv4(ip4(198, 51, 100, 200), ip4(198, 51, 100, 20)));

    NonTerminalIpContextBuilder swapped {};
    PFL_REQUIRE(swapped.push_ipv4(ip4(203, 0, 113, 10), ip4(203, 0, 113, 100)));
    PFL_REQUIRE(swapped.push_ipv4(ip4(198, 51, 100, 20), ip4(198, 51, 100, 200)));

    NonTerminalIpContextBuilder distinct {};
    PFL_REQUIRE(distinct.push_ipv4(ip4(203, 0, 113, 10), ip4(203, 0, 113, 100)));
    PFL_REQUIRE(distinct.push_ipv4(ip4(198, 51, 100, 21), ip4(198, 51, 100, 200)));

    const auto endpoint = ip4(10, 0, 0, 1);
    const auto first_context = canonicalize_ipv4(observed, endpoint, 443U, endpoint, 443U);
    const auto second_context = canonicalize_ipv4(swapped, endpoint, 443U, endpoint, 443U);
    const auto distinct_context = canonicalize_ipv4(distinct, endpoint, 443U, endpoint, 443U);

    NonTerminalIpContextRegistry registry {};
    const auto first_id = registry.intern(first_context);
    const auto second_id = registry.intern(second_context);
    const auto distinct_id = registry.intern(distinct_context);

    PFL_EXPECT(first_id == second_id);
    PFL_EXPECT(first_id != distinct_id);
}

void expect_ipv6_canonicalization_matches_reverse() {
    NonTerminalIpContextBuilder forward {};
    PFL_REQUIRE(forward.push_ipv6(ip6(1), ip6(2)));

    NonTerminalIpContextBuilder reverse {};
    PFL_REQUIRE(reverse.push_ipv6(ip6(2), ip6(1)));

    const auto forward_context = canonicalize_ipv6(forward, ip6(10), 1234U, ip6(20), 443U);
    const auto reverse_context = canonicalize_ipv6(reverse, ip6(20), 443U, ip6(10), 1234U);

    NonTerminalIpContextRegistry registry {};
    PFL_EXPECT(registry.intern(forward_context) == registry.intern(reverse_context));
}

void expect_mixed_ipv4_ipv6_canonicalization_matches_reverse() {
    NonTerminalIpContextBuilder forward {};
    PFL_REQUIRE(forward.push_ipv4(ip4(203, 0, 113, 1), ip4(203, 0, 113, 2)));
    PFL_REQUIRE(forward.push_ipv6(ip6(30), ip6(40)));

    NonTerminalIpContextBuilder reverse {};
    PFL_REQUIRE(reverse.push_ipv4(ip4(203, 0, 113, 2), ip4(203, 0, 113, 1)));
    PFL_REQUIRE(reverse.push_ipv6(ip6(40), ip6(30)));

    const auto forward_context = canonicalize_ipv4(forward, ip4(10, 0, 0, 1), 1111U, ip4(10, 0, 0, 2), 2222U);
    const auto reverse_context = canonicalize_ipv4(reverse, ip4(10, 0, 0, 2), 2222U, ip4(10, 0, 0, 1), 1111U);

    NonTerminalIpContextRegistry registry {};
    PFL_EXPECT(registry.intern(forward_context) == registry.intern(reverse_context));
}

void expect_builder_overflow_is_reported_and_not_empty() {
    NonTerminalIpContextBuilder builder {};
    for (std::size_t index = 0; index < kMaxNonTerminalIpContextLevels; ++index) {
        PFL_EXPECT(builder.push_ipv4(
            ip4(10, 0, 0, static_cast<std::uint8_t>(index + 1U)),
            ip4(10, 0, 1, static_cast<std::uint8_t>(index + 1U))
        ));
    }

    PFL_EXPECT(builder.full());
    PFL_EXPECT(builder.size() == kMaxNonTerminalIpContextLevels);
    PFL_EXPECT(!builder.overflowed());
    PFL_EXPECT(!builder.empty());

    PFL_EXPECT(!builder.push_ipv4(ip4(10, 0, 0, 250), ip4(10, 0, 1, 250)));
    PFL_EXPECT(builder.overflowed());
    PFL_EXPECT(builder.size() == kMaxNonTerminalIpContextLevels);
    PFL_EXPECT(!builder.empty());
    PFL_EXPECT(!builder.to_context().has_value());

    NonTerminalIpContextRegistry registry {};
    const auto valid_context = NonTerminalIpContext {
        NonTerminalIpLevel::ipv4(ip4(10, 0, 0, 1), ip4(10, 0, 1, 1)),
    };
    PFL_EXPECT(registry.intern(valid_context) != kEmptyNonTerminalIpContextId);
}

void expect_registry_retrieval_returns_canonical_context() {
    NonTerminalIpContextBuilder builder {};
    PFL_REQUIRE(builder.push_ipv4(ip4(203, 0, 113, 2), ip4(203, 0, 113, 1)));
    PFL_REQUIRE(builder.push_ipv6(ip6(12), ip6(11)));

    const auto canonical = canonicalize_ipv4(builder, ip4(10, 0, 0, 2), 443U, ip4(10, 0, 0, 1), 50000U);

    NonTerminalIpContextRegistry registry {};
    const auto id = registry.intern(canonical);
    PFL_EXPECT(id != kEmptyNonTerminalIpContextId);

    const auto* found = registry.find(id);
    PFL_REQUIRE(found != nullptr);
    PFL_EXPECT(*found == canonical);
    PFL_EXPECT(registry.find(kEmptyNonTerminalIpContextId) == nullptr);
}

void expect_hash_matches_equality_contract() {
    const NonTerminalIpContext first {
        NonTerminalIpLevel::ipv4(ip4(192, 0, 2, 1), ip4(192, 0, 2, 2)),
        NonTerminalIpLevel::ipv6(ip6(1), ip6(2)),
    };
    const NonTerminalIpContext equivalent {
        NonTerminalIpLevel::ipv4(ip4(192, 0, 2, 1), ip4(192, 0, 2, 2)),
        NonTerminalIpLevel::ipv6(ip6(1), ip6(2)),
    };
    const NonTerminalIpContext different {
        NonTerminalIpLevel::ipv6(ip6(1), ip6(2)),
        NonTerminalIpLevel::ipv4(ip4(192, 0, 2, 1), ip4(192, 0, 2, 2)),
    };

    PFL_EXPECT(first == equivalent);
    PFL_EXPECT(std::hash<NonTerminalIpContext> {}(first) == std::hash<NonTerminalIpContext> {}(equivalent));
    PFL_EXPECT(first != different);
}

}  // namespace

void run_non_terminal_ip_context_tests() {
    expect_empty_context_uses_reserved_id();
    expect_basic_ipv4_context_interns_once();
    expect_basic_ipv6_context_interns_once();
    expect_mixed_nested_context_retains_order_and_family();
    expect_distinct_addresses_level_counts_and_order_remain_distinct();
    expect_forward_reverse_ipv4_canonicalization_matches();
    expect_same_terminal_direction_with_different_carrier_context_splits();
    expect_equal_terminal_endpoint_tie_case_is_whole_context_canonical();
    expect_ipv6_canonicalization_matches_reverse();
    expect_mixed_ipv4_ipv6_canonicalization_matches_reverse();
    expect_builder_overflow_is_reported_and_not_empty();
    expect_registry_retrieval_returns_canonical_context();
    expect_hash_matches_equality_contract();
}

}  // namespace pfl::tests
