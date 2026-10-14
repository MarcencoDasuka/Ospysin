package com.ospysin.shared.error;

import lombok.Getter;

import java.util.List;

@Getter
public class ValidationException extends RuntimeException {

    private final List<InvalidParam> invalidParams;

    public ValidationException(String message) {
        super(message);
        this.invalidParams = List.of();
    }

    public ValidationException(String message, List<InvalidParam> invalidParams) {
        super(message);
        this.invalidParams = invalidParams != null ? invalidParams : List.of();
    }
}
