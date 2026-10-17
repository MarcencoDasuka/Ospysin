package com.ospysin.shared.error;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.ConstraintViolationException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.csrf.InvalidCsrfTokenException;
import org.springframework.security.web.csrf.MissingCsrfTokenException;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.validation.FieldError;
import org.springframework.web.HttpMediaTypeNotAcceptableException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.async.AsyncRequestTimeoutException;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

@Slf4j
@RestControllerAdvice
@RequiredArgsConstructor
public class GlobalExceptionHandler {

    private final Clock clock;

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ProblemDetail> handleValidation(MethodArgumentNotValidException ex, HttpServletRequest request) {
        List<InvalidParam> invalidParams = new ArrayList<>();
        for (FieldError fieldError : ex.getBindingResult().getFieldErrors()) {
            invalidParams.add(new InvalidParam(fieldError.getField(), fieldError.getDefaultMessage()));
        }

        ProblemDetail problem = buildProblemDetail(
                HttpStatus.UNPROCESSABLE_ENTITY,
                "https://ospysin.dev/errors/validation-error",
                "Validation Failed",
                "One or more request parameters failed validation.",
                request.getRequestURI()
        );
        problem.setProperty("invalidParams", invalidParams);

        return ResponseEntity
                .status(HttpStatus.UNPROCESSABLE_ENTITY)
                .contentType(MediaType.APPLICATION_PROBLEM_JSON)
                .body(problem);
    }

    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<ProblemDetail> handleConstraintViolation(ConstraintViolationException ex, HttpServletRequest request) {
        List<InvalidParam> invalidParams = new ArrayList<>();
        ex.getConstraintViolations().forEach(violation -> {
            String property = violation.getPropertyPath() != null ? violation.getPropertyPath().toString() : "parameter";
            invalidParams.add(new InvalidParam(property, violation.getMessage()));
        });

        ProblemDetail problem = buildProblemDetail(
                HttpStatus.UNPROCESSABLE_ENTITY,
                "https://ospysin.dev/errors/validation-error",
                "Validation Failed",
                ex.getMessage(),
                request.getRequestURI()
        );
        problem.setProperty("invalidParams", invalidParams);

        return ResponseEntity
                .status(HttpStatus.UNPROCESSABLE_ENTITY)
                .contentType(MediaType.APPLICATION_PROBLEM_JSON)
                .body(problem);
    }

    @ExceptionHandler(ValidationException.class)
    public ResponseEntity<ProblemDetail> handleCustomValidation(ValidationException ex, HttpServletRequest request) {
        ProblemDetail problem = buildProblemDetail(
                HttpStatus.UNPROCESSABLE_ENTITY,
                "https://ospysin.dev/errors/validation-error",
                "Validation Failed",
                ex.getMessage(),
                request.getRequestURI()
        );
        if (!ex.getInvalidParams().isEmpty()) {
            problem.setProperty("invalidParams", ex.getInvalidParams());
        }

        return ResponseEntity
                .status(HttpStatus.UNPROCESSABLE_ENTITY)
                .contentType(MediaType.APPLICATION_PROBLEM_JSON)
                .body(problem);
    }

    @ExceptionHandler(PolicyViolationException.class)
    public ResponseEntity<ProblemDetail> handlePolicyViolation(PolicyViolationException ex, HttpServletRequest request) {
        ProblemDetail problem = buildProblemDetail(
                HttpStatus.FORBIDDEN,
                "https://ospysin.dev/errors/policy-violation",
                "Policy Engine Rejection",
                ex.getMessage(),
                request.getRequestURI()
        );
        if (!ex.getInvalidParams().isEmpty()) {
            problem.setProperty("invalidParams", ex.getInvalidParams());
        }

        return ResponseEntity
                .status(HttpStatus.FORBIDDEN)
                .contentType(MediaType.APPLICATION_PROBLEM_JSON)
                .body(problem);
    }

    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<ProblemDetail> handleNotFound(ResourceNotFoundException ex, HttpServletRequest request) {
        ProblemDetail problem = buildProblemDetail(
                HttpStatus.NOT_FOUND,
                "https://ospysin.dev/errors/resource-not-found",
                "Resource Not Found",
                ex.getMessage(),
                request.getRequestURI()
        );

        return ResponseEntity
                .status(HttpStatus.NOT_FOUND)
                .contentType(MediaType.APPLICATION_PROBLEM_JSON)
                .body(problem);
    }

    @ExceptionHandler(ConflictException.class)
    public ResponseEntity<ProblemDetail> handleConflict(ConflictException ex, HttpServletRequest request) {
        ProblemDetail problem = buildProblemDetail(
                HttpStatus.CONFLICT,
                "https://ospysin.dev/errors/conflict",
                "Conflict",
                ex.getMessage(),
                request.getRequestURI()
        );

        return ResponseEntity
                .status(HttpStatus.CONFLICT)
                .contentType(MediaType.APPLICATION_PROBLEM_JSON)
                .body(problem);
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ProblemDetail> handleAccessDenied(AccessDeniedException ex, HttpServletRequest request) {
        String detail = "You do not have permission to perform this action.";
        if (ex instanceof MissingCsrfTokenException || ex instanceof InvalidCsrfTokenException) {
            detail = "CSRF token is missing or invalid.";
        }

        ProblemDetail problem = buildProblemDetail(
                HttpStatus.FORBIDDEN,
                "https://ospysin.dev/errors/access-denied",
                "Access Denied",
                detail,
                request.getRequestURI()
        );

        return ResponseEntity
                .status(HttpStatus.FORBIDDEN)
                .contentType(MediaType.APPLICATION_PROBLEM_JSON)
                .body(problem);
    }

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ProblemDetail> handleAuthentication(AuthenticationException ex, HttpServletRequest request) {
        String detail = ex instanceof BadCredentialsException
                ? "Invalid username or password."
                : "Authentication is required to access this resource.";

        ProblemDetail problem = buildProblemDetail(
                HttpStatus.UNAUTHORIZED,
                "https://ospysin.dev/errors/unauthorized",
                "Unauthorized",
                detail,
                request.getRequestURI()
        );

        return ResponseEntity
                .status(HttpStatus.UNAUTHORIZED)
                .contentType(MediaType.APPLICATION_PROBLEM_JSON)
                .body(problem);
    }

    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<ProblemDetail> handleMethodNotSupported(HttpRequestMethodNotSupportedException ex, HttpServletRequest request) {
        ProblemDetail problem = buildProblemDetail(
                HttpStatus.METHOD_NOT_ALLOWED,
                "https://ospysin.dev/errors/method-not-allowed",
                "Method Not Allowed",
                ex.getMessage(),
                request.getRequestURI()
        );

        return ResponseEntity
                .status(HttpStatus.METHOD_NOT_ALLOWED)
                .contentType(MediaType.APPLICATION_PROBLEM_JSON)
                .body(problem);
    }

    @ExceptionHandler({HttpMessageNotReadableException.class, MethodArgumentTypeMismatchException.class})
    public ResponseEntity<ProblemDetail> handleMalformedRequest(Exception ex, HttpServletRequest request) {
        String detail = "Malformed request payload or invalid parameter format.";
        if (ex instanceof HttpMessageNotReadableException) {
            detail = "Malformed JSON request body or unreadable input.";
        } else if (ex instanceof MethodArgumentTypeMismatchException mismatchEx) {
            detail = "Invalid value for parameter '" + mismatchEx.getName() + "'.";
        }

        ProblemDetail problem = buildProblemDetail(
                HttpStatus.BAD_REQUEST,
                "https://ospysin.dev/errors/bad-request",
                "Bad Request",
                detail,
                request.getRequestURI()
        );

        return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .contentType(MediaType.APPLICATION_PROBLEM_JSON)
                .body(problem);
    }

    @ExceptionHandler({IllegalArgumentException.class, IllegalStateException.class})
    public ResponseEntity<ProblemDetail> handleBadRequest(RuntimeException ex, HttpServletRequest request) {
        ProblemDetail problem = buildProblemDetail(
                HttpStatus.BAD_REQUEST,
                "https://ospysin.dev/errors/bad-request",
                "Bad Request",
                ex.getMessage(),
                request.getRequestURI()
        );

        return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .contentType(MediaType.APPLICATION_PROBLEM_JSON)
                .body(problem);
    }

    @ExceptionHandler(HttpMediaTypeNotAcceptableException.class)
    public ResponseEntity<ProblemDetail> handleMediaTypeNotAcceptable(
            HttpMediaTypeNotAcceptableException ex,
            HttpServletRequest request
    ) {
        ProblemDetail problem = buildProblemDetail(
                HttpStatus.NOT_ACCEPTABLE,
                "https://ospysin.dev/errors/not-acceptable",
                "Not Acceptable",
                ex.getMessage() != null ? ex.getMessage() : "Requested media type is not supported",
                request.getRequestURI()
        );
        return ResponseEntity.status(HttpStatus.NOT_ACCEPTABLE)
                .contentType(MediaType.APPLICATION_PROBLEM_JSON)
                .body(problem);
    }

    @ExceptionHandler(AsyncRequestTimeoutException.class)
    public ResponseEntity<Void> handleAsyncRequestTimeout(
            AsyncRequestTimeoutException ex,
            HttpServletRequest request
    ) {
        log.debug("Async request timed out on {} {}", request.getMethod(), request.getRequestURI());
        return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ProblemDetail> handleGenericException(Exception ex, HttpServletRequest request) {
        log.error("Unhandled internal server error occurred while processing request {}", request.getRequestURI(), ex);

        ProblemDetail problem = buildProblemDetail(
                HttpStatus.INTERNAL_SERVER_ERROR,
                "https://ospysin.dev/errors/internal-error",
                "Internal Server Error",
                "An unexpected internal error occurred. Please consult server administrator logs.",
                request.getRequestURI()
        );

        return ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .contentType(MediaType.APPLICATION_PROBLEM_JSON)
                .body(problem);
    }

    private ProblemDetail buildProblemDetail(HttpStatus status, String type, String title, String detail, String instance) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(status, detail);
        problem.setType(URI.create(type));
        problem.setTitle(title);
        problem.setInstance(URI.create(instance));
        problem.setProperty("timestamp", Instant.now(clock).toString());
        return problem;
    }
}
