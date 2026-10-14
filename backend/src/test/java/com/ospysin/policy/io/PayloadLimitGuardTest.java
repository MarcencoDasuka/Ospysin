package com.ospysin.policy.io;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.zip.GZIPOutputStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PayloadLimitGuardTest {

    @Test
    @DisplayName("Tier 1 Wire Cap: Reading more raw bytes than allowed throws PayloadLimitExceededException")
    void tier1WireCapViolation() {
        byte[] payload = new byte[64 * 1024]; // 64 KB
        Arrays.fill(payload, (byte) 'A');

        long wireCap = 32 * 1024; // 32 KB limit
        BoundedWireInputStream wireStream = new BoundedWireInputStream(new ByteArrayInputStream(payload), wireCap);

        byte[] buffer = new byte[8192];
        assertThatThrownBy(() -> {
            while (wireStream.read(buffer) != -1) {
                // Read until exception
            }
        }).isInstanceOf(PayloadLimitExceededException.class)
                .hasMessageContaining("Wire bytes cap exceeded");
    }

    @Test
    @DisplayName("Tier 2 Decompressed Cap: Reading more decompressed bytes than allowed throws PayloadLimitExceededException")
    void tier2DecompressedCapViolation() {
        byte[] payload = new byte[128 * 1024]; // 128 KB
        Arrays.fill(payload, (byte) 'B');

        long maxDecompressed = 64 * 1024; // 64 KB limit
        // Wire supplier returns 1:1 wire bytes so expansion ratio is 1.0 (not a bomb)
        BoundedResponseStream responseStream = new BoundedResponseStream(
                new ByteArrayInputStream(payload),
                () -> 128 * 1024L,
                maxDecompressed
        );

        byte[] buffer = new byte[8192];
        assertThatThrownBy(() -> {
            while (responseStream.read(buffer) != -1) {
                // Read until exception
            }
        }).isInstanceOf(PayloadLimitExceededException.class)
                .hasMessageContaining("Decompressed bytes cap exceeded");
    }

    @Test
    @DisplayName("Tier 2 Bomb Ratio: 50 KB decompressed from 1 KB wire is allowed because D <= 100 KB")
    void decompressionUnder100KbAllowedRegardlessOfRatio() throws IOException {
        byte[] payload = new byte[50 * 1024]; // 50 KB decompressed
        Arrays.fill(payload, (byte) 'C');

        // Wire bytes reported as 1 KB (ratio is 50:1, but D <= 100 KB threshold)
        BoundedResponseStream responseStream = new BoundedResponseStream(
                new ByteArrayInputStream(payload),
                () -> 1024L, // 1 KB wire
                2 * 1024 * 1024L // 2 MB max
        );

        byte[] buffer = new byte[4096];
        long totalRead = 0;
        int n;
        while ((n = responseStream.read(buffer)) != -1) {
            totalRead += n;
        }

        assertThat(totalRead).isEqualTo(50 * 1024);
        assertThat(responseStream.getDecompressedBytesRead()).isEqualTo(50 * 1024);
    }

    @Test
    @DisplayName("Tier 2 Bomb Ratio: 150 KB decompressed from 5 KB wire throws DecompressionBombException (D > 100 KB and ratio 30 > 10)")
    void decompressionBombRatioViolation() {
        byte[] payload = new byte[150 * 1024]; // 150 KB decompressed
        Arrays.fill(payload, (byte) 'D');

        // Wire bytes reported as 5 KB (ratio = 30 > 10, and D > 100 KB)
        BoundedResponseStream responseStream = new BoundedResponseStream(
                new ByteArrayInputStream(payload),
                () -> 5 * 1024L, // 5 KB wire
                2 * 1024 * 1024L
        );

        byte[] buffer = new byte[4096];
        assertThatThrownBy(() -> {
            while (responseStream.read(buffer) != -1) {
                // Read until exception
            }
        }).isInstanceOf(DecompressionBombException.class)
                .hasMessageContaining("Decompression bomb detected")
                .hasMessageContaining("expansion ratio");
    }

    @Test
    @DisplayName("Live GZIP Decompression Bomb: Real compressed repeated payload triggers DecompressionBombException")
    void realGzipDecompressionBomb() throws IOException {
        // Create a real gzip bomb: 200 KB of zeros compresses to ~200 bytes
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (GZIPOutputStream gzos = new GZIPOutputStream(baos)) {
            byte[] zeros = new byte[200 * 1024]; // 200 KB uncompressed
            gzos.write(zeros);
        }
        byte[] compressedBytes = baos.toByteArray();
        assertThat(compressedBytes.length).isLessThan(1024); // < 1 KB wire

        BoundedResponseStream guardedStream = PayloadLimitGuard.wrap(
                new ByteArrayInputStream(compressedBytes),
                1024 * 1024L,     // 1 MB wire cap
                2 * 1024 * 1024L, // 2 MB decompressed cap
                true              // isGzip
        );

        byte[] buffer = new byte[4096];
        assertThatThrownBy(() -> {
            while (guardedStream.read(buffer) != -1) {
                // Read until ratio triggers
            }
        }).isInstanceOf(DecompressionBombException.class)
                .hasMessageContaining("Decompression bomb detected");
    }

    @Test
    @DisplayName("Tier 3 Aggregate Budget: Exhaustion across multiple assets throws PayloadLimitExceededException")
    void tier3AggregateBudgetExhaustion() throws IOException {
        AggregatePayloadBudget budget = new AggregatePayloadBudget(5 * 1024 * 1024L); // 5 MB

        // Asset 1: 3 MB
        byte[] asset1 = new byte[3 * 1024 * 1024];
        BoundedResponseStream stream1 = new BoundedResponseStream(
                new ByteArrayInputStream(asset1),
                () -> 3 * 1024 * 1024L,
                4 * 1024 * 1024L,
                budget
        );
        byte[] buf = new byte[64 * 1024];
        while (stream1.read(buf) != -1) {
            // Read all 3 MB
        }
        assertThat(budget.getConsumedBytes()).isEqualTo(3 * 1024 * 1024L);
        assertThat(budget.getRemainingBytes()).isEqualTo(2 * 1024 * 1024L);

        // Asset 2: 2.5 MB (total would be 5.5 MB > 5 MB)
        byte[] asset2 = new byte[2560 * 1024];
        BoundedResponseStream stream2 = new BoundedResponseStream(
                new ByteArrayInputStream(asset2),
                () -> 2560 * 1024L,
                4 * 1024 * 1024L,
                budget
        );

        assertThatThrownBy(() -> {
            while (stream2.read(buf) != -1) {
                // Read until budget exhausted
            }
        }).isInstanceOf(PayloadLimitExceededException.class)
                .hasMessageContaining("Aggregate payload budget exceeded");

        // Test budget reset
        budget.reset();
        assertThat(budget.getConsumedBytes()).isEqualTo(0);
        assertThat(budget.getRemainingBytes()).isEqualTo(5 * 1024 * 1024L);
    }

    @Test
    @DisplayName("Stream skip operation tracks bytes and enforces bounds")
    void streamSkipTracking() throws IOException {
        byte[] payload = new byte[64 * 1024];
        BoundedWireInputStream wireStream = new BoundedWireInputStream(new ByteArrayInputStream(payload), 32 * 1024);

        assertThatThrownBy(() -> wireStream.skip(40 * 1024))
                .isInstanceOf(PayloadLimitExceededException.class);
    }
}
