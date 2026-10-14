package com.ospysin.policy.io;

import java.io.IOException;
import java.io.InputStream;
import java.util.zip.GZIPInputStream;

public final class PayloadLimitGuard {

    public static final long DEFAULT_WIRE_CAP = 1024 * 1024L; // 1 MB
    public static final long DEFAULT_DECOMPRESSED_CAP = 2 * 1024 * 1024L; // 2 MB
    public static final long DEFAULT_AGGREGATE_CAP = 5 * 1024 * 1024L; // 5 MB

    private PayloadLimitGuard() {
    }

    public static BoundedResponseStream wrap(InputStream rawStream, long wireCap, long decompressedCap,
                                             boolean isGzip, AggregatePayloadBudget aggregateBudget) throws IOException {
        BoundedWireInputStream wireStream = new BoundedWireInputStream(rawStream, wireCap);
        InputStream contentStream = isGzip ? new GZIPInputStream(wireStream) : wireStream;
        return new BoundedResponseStream(contentStream, wireStream::getBytesRead, decompressedCap, aggregateBudget);
    }

    public static BoundedResponseStream wrap(InputStream rawStream, long wireCap, long decompressedCap,
                                             boolean isGzip) throws IOException {
        return wrap(rawStream, wireCap, decompressedCap, isGzip, null);
    }

    public static BoundedResponseStream wrap(InputStream rawStream, boolean isGzip) throws IOException {
        return wrap(rawStream, DEFAULT_WIRE_CAP, DEFAULT_DECOMPRESSED_CAP, isGzip, null);
    }
}
