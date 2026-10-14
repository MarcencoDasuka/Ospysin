package com.ospysin.execution;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;

import static org.assertj.core.api.Assertions.assertThat;

class HostRateLimiterTest {

    private MutableClock clock;
    private HostRateLimiter rateLimiter;

    private static class MutableClock extends Clock {
        private Instant currentInstant;
        private final ZoneId zone;

        MutableClock(Instant start, ZoneId zone) {
            this.currentInstant = start;
            this.zone = zone;
        }

        @Override
        public ZoneId getZone() {
            return zone;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return new MutableClock(currentInstant, zone);
        }

        @Override
        public Instant instant() {
            return currentInstant;
        }

        public void advanceMillis(long ms) {
            this.currentInstant = this.currentInstant.plusMillis(ms);
        }
    }

    @BeforeEach
    void setUp() {
        clock = new MutableClock(Instant.parse("2026-10-15T00:00:00Z"), ZoneOffset.UTC);
        rateLimiter = new HostRateLimiter(clock);
    }

    @Test
    @DisplayName("HostRateLimiter enforces 2 requests/second with 500ms spacing per host")
    void enforcesRateLimitAndSpacing() {
        String host = "example.com";

        // 1st request at t=0ms: should succeed
        assertThat(rateLimiter.tryAcquire(host)).isTrue();

        // Immediate 2nd request at t=100ms: spacing violated (<500ms), should fail
        clock.advanceMillis(100);
        assertThat(rateLimiter.tryAcquire(host)).isFalse();

        // 2nd request at t=500ms: spacing satisfied, should succeed
        clock.advanceMillis(400); // now at 500ms
        assertThat(rateLimiter.tryAcquire(host)).isTrue();

        // 3rd request at t=700ms: spacing violated (<500ms since last acquire), should fail
        clock.advanceMillis(200); // now at 700ms
        assertThat(rateLimiter.tryAcquire(host)).isFalse();

        // 3rd request at t=1000ms: spacing satisfied and 1 second passed, should succeed
        clock.advanceMillis(300); // now at 1000ms
        assertThat(rateLimiter.tryAcquire(host)).isTrue();
    }

    @Test
    @DisplayName("HostRateLimiter enforces rate limits independently per target host")
    void independentHostLimits() {
        String hostA = "alpha.com";
        String hostB = "beta.com";

        // Acquire for hostA at t=0ms
        assertThat(rateLimiter.tryAcquire(hostA)).isTrue();

        // Immediate acquire for hostB at t=10ms should succeed because it is an independent host
        clock.advanceMillis(10);
        assertThat(rateLimiter.tryAcquire(hostB)).isTrue();

        // Immediate second acquire for hostA should still fail
        assertThat(rateLimiter.tryAcquire(hostA)).isFalse();
    }

    @Test
    @DisplayName("HostRateLimiter normalizes hosts with ports and protocols")
    void normalizesHosts() {
        assertThat(rateLimiter.tryAcquire("https://target.com:8443/api")).isTrue();
        // Same underlying host immediately fails
        clock.advanceMillis(50);
        assertThat(rateLimiter.tryAcquire("target.com:8443")).isFalse();
    }

    @Test
    @DisplayName("reset clears all rate limiter buckets")
    void resetClearsBuckets() {
        String host = "target.com";
        assertThat(rateLimiter.tryAcquire(host)).isTrue();
        clock.advanceMillis(10);
        assertThat(rateLimiter.tryAcquire(host)).isFalse();

        rateLimiter.reset();
        // After reset, fresh bucket allows acquire
        assertThat(rateLimiter.tryAcquire(host)).isTrue();
    }

    @Test
    @DisplayName("null or blank host is safe and returns true")
    void nullOrBlankHost() {
        assertThat(rateLimiter.tryAcquire(null)).isTrue();
        assertThat(rateLimiter.tryAcquire("   ")).isTrue();
    }

    @Test
    @DisplayName("HostRateLimiter normalizes bracketed and unbracketed IPv6 addresses correctly")
    void normalizesIpv6Hosts() {
        // First acquire with bracketed IPv6 and port
        assertThat(rateLimiter.tryAcquire("[2001:db8::1]:8080")).isTrue();

        // Immediate acquire with raw IPv6 without port maps to same host -> rate limited
        clock.advanceMillis(50);
        assertThat(rateLimiter.tryAcquire("2001:db8::1")).isFalse();

        // Immediate acquire with full URL containing IPv6 maps to same host -> rate limited
        clock.advanceMillis(50);
        assertThat(rateLimiter.tryAcquire("https://[2001:db8::1]:8080/test")).isFalse();

        // Distinct IPv6 address should succeed
        assertThat(rateLimiter.tryAcquire("2001:db8::2")).isTrue();
    }
}
