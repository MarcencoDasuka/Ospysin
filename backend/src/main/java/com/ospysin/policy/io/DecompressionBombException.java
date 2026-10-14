package com.ospysin.policy.io;

public class DecompressionBombException extends PayloadLimitExceededException {

    private final long decompressedBytes;
    private final long wireBytes;
    private final double ratio;

    public DecompressionBombException(String message) {
        super(message);
        this.decompressedBytes = -1;
        this.wireBytes = -1;
        this.ratio = -1;
    }

    public DecompressionBombException(String message, long decompressedBytes, long wireBytes, double ratio) {
        super(message);
        this.decompressedBytes = decompressedBytes;
        this.wireBytes = wireBytes;
        this.ratio = ratio;
    }

    public long getDecompressedBytes() {
        return decompressedBytes;
    }

    public long getWireBytes() {
        return wireBytes;
    }

    public double getRatio() {
        return ratio;
    }
}
