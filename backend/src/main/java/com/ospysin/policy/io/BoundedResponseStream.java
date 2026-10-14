package com.ospysin.policy.io;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.LongSupplier;

public class BoundedResponseStream extends FilterInputStream {

    public static final long DEFAULT_MAX_DECOMPRESSED_BYTES = 2 * 1024 * 1024L; // 2 MB
    public static final long BOMB_THRESHOLD_BYTES = 100 * 1024L; // 102,400 bytes (100 KB)
    public static final double MAX_EXPANSION_RATIO = 10.0;

    private final LongSupplier wireBytesSupplier;
    private final long maxDecompressedBytes;
    private final AggregatePayloadBudget aggregateBudget;
    private final AtomicLong decompressedBytesRead = new AtomicLong(0);

    public BoundedResponseStream(InputStream in) {
        this(in, null, DEFAULT_MAX_DECOMPRESSED_BYTES, null);
    }

    public BoundedResponseStream(InputStream in, long maxDecompressedBytes) {
        this(in, null, maxDecompressedBytes, null);
    }

    public BoundedResponseStream(InputStream in, LongSupplier wireBytesSupplier) {
        this(in, wireBytesSupplier, DEFAULT_MAX_DECOMPRESSED_BYTES, null);
    }

    public BoundedResponseStream(InputStream in, LongSupplier wireBytesSupplier, long maxDecompressedBytes) {
        this(in, wireBytesSupplier, maxDecompressedBytes, null);
    }

    public BoundedResponseStream(InputStream in, LongSupplier wireBytesSupplier,
                                 long maxDecompressedBytes, AggregatePayloadBudget aggregateBudget) {
        super(in);
        if (maxDecompressedBytes <= 0) {
            throw new IllegalArgumentException("maxDecompressedBytes must be positive");
        }
        this.wireBytesSupplier = wireBytesSupplier != null ? wireBytesSupplier : decompressedBytesRead::get;
        this.maxDecompressedBytes = maxDecompressedBytes;
        this.aggregateBudget = aggregateBudget;
    }

    @Override
    public int read() throws IOException {
        int b = super.read();
        if (b != -1) {
            trackDecompressed(1);
        }
        return b;
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        int n = super.read(b, off, len);
        if (n > 0) {
            trackDecompressed(n);
        }
        return n;
    }

    @Override
    public long skip(long n) throws IOException {
        long skipped = super.skip(n);
        if (skipped > 0) {
            trackDecompressed(skipped);
        }
        return skipped;
    }

    private void trackDecompressed(long count) throws IOException {
        long d = decompressedBytesRead.addAndGet(count);

        // 1. Tier 2: Decompressed bytes hard cap
        if (d > maxDecompressedBytes) {
            throw new PayloadLimitExceededException(
                    String.format("Decompressed bytes cap exceeded: %d bytes read (max allowed: %d bytes)", d, maxDecompressedBytes),
                    maxDecompressedBytes,
                    d
            );
        }

        // 2. Tier 2: Decompression bomb ratio check (activated once D > 100 KB)
        if (d > BOMB_THRESHOLD_BYTES) {
            long c = wireBytesSupplier.getAsLong();
            double ratio = (double) d / Math.max(c, 1L);
            if (ratio > MAX_EXPANSION_RATIO) {
                throw new DecompressionBombException(
                        String.format("Decompression bomb detected: %d decompressed bytes from %d wire bytes (expansion ratio: %.2f > %.1f)",
                                d, c, ratio, MAX_EXPANSION_RATIO),
                        d,
                        c,
                        ratio
                );
            }
        }

        // 3. Tier 3: Aggregate multi-asset budget tracker
        if (aggregateBudget != null) {
            aggregateBudget.track(count);
        }
    }

    public long getDecompressedBytesRead() {
        return decompressedBytesRead.get();
    }

    public long getMaxDecompressedBytes() {
        return maxDecompressedBytes;
    }

    public AggregatePayloadBudget getAggregateBudget() {
        return aggregateBudget;
    }
}
