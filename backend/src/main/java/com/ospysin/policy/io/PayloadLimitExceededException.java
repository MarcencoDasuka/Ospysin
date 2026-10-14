package com.ospysin.policy.io;

import java.io.IOException;

public class PayloadLimitExceededException extends IOException {

    private final long limit;
    private final long currentBytes;

    public PayloadLimitExceededException(String message) {
        super(message);
        this.limit = -1;
        this.currentBytes = -1;
    }

    public PayloadLimitExceededException(String message, long limit, long currentBytes) {
        super(message);
        this.limit = limit;
        this.currentBytes = currentBytes;
    }

    public long getLimit() {
        return limit;
    }

    public long getCurrentBytes() {
        return currentBytes;
    }
}
