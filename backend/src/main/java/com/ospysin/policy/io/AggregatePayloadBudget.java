package com.ospysin.policy.io;

import java.util.concurrent.atomic.AtomicLong;

public class AggregatePayloadBudget {

    public static final long DEFAULT_MAX_AGGREGATE_BYTES = 5 * 1024 * 1024L; // 5 MB

    private final long maxBytes;
    private final AtomicLong consumedBytes = new AtomicLong(0);

    public AggregatePayloadBudget() {
        this(DEFAULT_MAX_AGGREGATE_BYTES);
    }

    public AggregatePayloadBudget(long maxBytes) {
        if (maxBytes <= 0) {
            throw new IllegalArgumentException("maxBytes must be positive");
        }
        this.maxBytes = maxBytes;
    }

    public void track(long bytes) throws PayloadLimitExceededException {
        if (bytes <= 0) {
            return;
        }
        long updated = consumedBytes.addAndGet(bytes);
        if (updated > maxBytes) {
            throw new PayloadLimitExceededException(
                    String.format("Aggregate payload budget exceeded: %d bytes consumed (max allowed: %d bytes)", updated, maxBytes),
                    maxBytes,
                    updated
            );
        }
    }

    public long getConsumedBytes() {
        return consumedBytes.get();
    }

    public long getMaxBytes() {
        return maxBytes;
    }

    public long getRemainingBytes() {
        return Math.max(0, maxBytes - consumedBytes.get());
    }

    public void reset() {
        consumedBytes.set(0);
    }
}
