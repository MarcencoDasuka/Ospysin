package com.ospysin.policy.io;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.atomic.AtomicLong;

public class BoundedWireInputStream extends FilterInputStream {

    public static final long DEFAULT_MAX_WIRE_BYTES = 1024 * 1024L; // 1 MB

    private final long maxWireBytes;
    private final AtomicLong bytesRead = new AtomicLong(0);

    public BoundedWireInputStream(InputStream in) {
        this(in, DEFAULT_MAX_WIRE_BYTES);
    }

    public BoundedWireInputStream(InputStream in, long maxWireBytes) {
        super(in);
        if (maxWireBytes <= 0) {
            throw new IllegalArgumentException("maxWireBytes must be positive");
        }
        this.maxWireBytes = maxWireBytes;
    }

    @Override
    public int read() throws IOException {
        int b = super.read();
        if (b != -1) {
            checkLimit(1);
        }
        return b;
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        int n = super.read(b, off, len);
        if (n > 0) {
            checkLimit(n);
        }
        return n;
    }

    @Override
    public long skip(long n) throws IOException {
        long skipped = super.skip(n);
        if (skipped > 0) {
            checkLimit(skipped);
        }
        return skipped;
    }

    private void checkLimit(long count) throws PayloadLimitExceededException {
        long current = bytesRead.addAndGet(count);
        if (current > maxWireBytes) {
            throw new PayloadLimitExceededException(
                    String.format("Wire bytes cap exceeded: %d bytes read (max allowed: %d bytes)", current, maxWireBytes),
                    maxWireBytes,
                    current
            );
        }
    }

    public long getBytesRead() {
        return bytesRead.get();
    }

    public long getMaxWireBytes() {
        return maxWireBytes;
    }
}
