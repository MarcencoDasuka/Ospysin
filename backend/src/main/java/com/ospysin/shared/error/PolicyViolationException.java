package com.ospysin.shared.error;

import lombok.Getter;

import java.util.List;

@Getter
public class PolicyViolationException extends RuntimeException {

    private final List<InvalidParam> invalidParams;

    public PolicyViolationException(String message) {
        super(message);
        this.invalidParams = List.of();
    }

    public PolicyViolationException(String message, List<InvalidParam> invalidParams) {
        super(message);
        this.invalidParams = invalidParams != null ? invalidParams : List.of();
    }
}
