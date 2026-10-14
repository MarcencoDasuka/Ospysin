package com.ospysin.execution;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.util.Locale;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Per-host token bucket rate limiter enforcing a maximum of 2 requests/second per host with 500ms spacing.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class HostRateLimiter {

    public static final double MAX_TOKENS = 2.0;
    public static final double REFILL_PER_SECOND = 2.0;
    public static final long MIN_SPACING_MS = 500;

    private final Clock clock;
    private final ConcurrentHashMap<String, HostBucket> hostBuckets = new ConcurrentHashMap<>();

    private static class HostBucket {
        private double tokens = MAX_TOKENS;
        private Instant lastRefill;
        private Instant lastAcquired = Instant.EPOCH;

        HostBucket(Instant now) {
            this.lastRefill = now;
        }

        synchronized boolean tryAcquire(Instant now) {
            double elapsedSeconds = Math.max(0.0, (now.toEpochMilli() - lastRefill.toEpochMilli()) / 1000.0);
            tokens = Math.min(MAX_TOKENS, tokens + elapsedSeconds * REFILL_PER_SECOND);
            lastRefill = now;

            long msSinceLastAcquire = now.toEpochMilli() - lastAcquired.toEpochMilli();
            if (tokens >= 1.0 && (lastAcquired.equals(Instant.EPOCH) || msSinceLastAcquire >= MIN_SPACING_MS)) {
                tokens -= 1.0;
                lastAcquired = now;
                return true;
            }
            return false;
        }
    }

    /**
     * Attempts to acquire an execution slot for the host without blocking.
     *
     * @param host the target hostname or IP
     * @return true if acquired, false if rate limited
     */
    public boolean tryAcquire(String host) {
        if (host == null || host.isBlank()) {
            return true;
        }
        String normalized = normalizeHost(host);
        Instant now = clock.instant();
        HostBucket bucket = hostBuckets.computeIfAbsent(normalized, k -> new HostBucket(now));
        return bucket.tryAcquire(now);
    }

    /**
     * Blocks until a rate limit slot is acquired for the host.
     *
     * @param host the target hostname or IP
     */
    public void acquire(String host) {
        if (host == null || host.isBlank()) {
            return;
        }
        String normalized = normalizeHost(host);
        while (true) {
            Instant now = clock.instant();
            HostBucket bucket = hostBuckets.computeIfAbsent(normalized, k -> new HostBucket(now));
            if (bucket.tryAcquire(now)) {
                return;
            }
            try {
                Thread.sleep(50);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("Interrupted while waiting for rate limiter token for host " + host, e);
            }
        }
    }

    public void reset() {
        hostBuckets.clear();
    }

    private String normalizeHost(String host) {
        if (host == null || host.isBlank()) {
            return "";
        }
        String trimmed = host.trim().toLowerCase(Locale.ROOT);
        try {
            if (trimmed.contains("://")) {
                URI uri = URI.create(trimmed);
                if (uri.getHost() != null) {
                    trimmed = uri.getHost().toLowerCase(Locale.ROOT);
                }
            }
        } catch (Exception ignored) {
        }
        int slash = trimmed.indexOf('/');
        if (slash >= 0) {
            trimmed = trimmed.substring(0, slash);
        }
        int lastBracket = trimmed.lastIndexOf(']');
        if (lastBracket >= 0) {
            int colonAfter = trimmed.indexOf(':', lastBracket);
            if (colonAfter > 0) {
                trimmed = trimmed.substring(0, colonAfter);
            }
        } else {
            int firstColon = trimmed.indexOf(':');
            int lastColon = trimmed.lastIndexOf(':');
            if (firstColon >= 0 && firstColon == lastColon) {
                trimmed = trimmed.substring(0, firstColon);
            }
        }
        if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
            trimmed = trimmed.substring(1, trimmed.length() - 1);
        }
        return trimmed;
    }
}
