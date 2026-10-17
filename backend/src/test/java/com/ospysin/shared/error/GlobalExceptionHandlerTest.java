package com.ospysin.shared.error;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.*;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.List;

import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

class GlobalExceptionHandlerTest {

    private MockMvc mockMvc;

    @RestController
    @RequestMapping("/test")
    static class TestController {

        record TestRequest(
                @NotBlank(message = "Username cannot be blank")
                @Size(min = 3, max = 20, message = "Username must be between 3 and 20 characters")
                String username
        ) {}

        @PostMapping("/validate")
        public String testValidation(@Valid @RequestBody TestRequest request) {
            return "ok";
        }

        @GetMapping("/not-found")
        public String testNotFound() {
            throw new ResourceNotFoundException("Entity with id 123 was not found");
        }

        @GetMapping("/policy-violation")
        public String testPolicy() {
            throw new PolicyViolationException(
                    "Target resolves to private network 192.168.1.100 while session is in PUBLIC mode.",
                    List.of(new InvalidParam("targetUrl", "Resolves to prohibited special-purpose IP range."))
            );
        }

        @GetMapping("/conflict")
        public String testConflict() {
            throw new ConflictException("Another execution is currently RUNNING");
        }

        @GetMapping("/internal-error")
        public String testInternalError() {
            throw new RuntimeException("Sensitive SQL query: SELECT * FROM secrets; connection timeout");
        }

        @GetMapping("/param/{id}")
        public String testParamMismatch(@PathVariable("id") java.util.UUID id) {
            return id.toString();
        }

        @GetMapping("/media-not-acceptable")
        public String testMediaNotAcceptable() throws org.springframework.web.HttpMediaTypeNotAcceptableException {
            throw new org.springframework.web.HttpMediaTypeNotAcceptableException("No acceptable representation");
        }

        @GetMapping("/async-timeout")
        public String testAsyncTimeout() {
            throw new org.springframework.web.context.request.async.AsyncRequestTimeoutException();
        }
    }

    @BeforeEach
    void setUp() {
        Clock fixedClock = Clock.fixed(Instant.parse("2026-10-13T20:00:00Z"), ZoneId.of("UTC"));
        GlobalExceptionHandler handler = new GlobalExceptionHandler(fixedClock);
        mockMvc = MockMvcBuilders.standaloneSetup(new TestController())
                .setControllerAdvice(handler)
                .build();
    }

    @Test
    @DisplayName("Returns 422 Unprocessable Entity with RFC 9457 Problem Details and invalidParams on validation error")
    void shouldReturn422WithInvalidParamsOnValidationFailure() throws Exception {
        String invalidJson = """
                {
                    "username": ""
                }
                """;

        mockMvc.perform(post("/test/validate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(invalidJson))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(header().string("Content-Type", MediaType.APPLICATION_PROBLEM_JSON_VALUE))
                .andExpect(jsonPath("$.type").value("https://ospysin.dev/errors/validation-error"))
                .andExpect(jsonPath("$.title").value("Validation Failed"))
                .andExpect(jsonPath("$.status").value(422))
                .andExpect(jsonPath("$.instance").value("/test/validate"))
                .andExpect(jsonPath("$.timestamp").value("2026-10-13T20:00:00Z"))
                .andExpect(jsonPath("$.invalidParams", hasSize(greaterThanOrEqualTo(1))))
                .andExpect(jsonPath("$.invalidParams[*].name", hasItem("username")));
    }

    @Test
    @DisplayName("Returns 403 Forbidden with RFC 9457 Problem Details on policy violation")
    void shouldReturn403OnPolicyViolation() throws Exception {
        mockMvc.perform(get("/test/policy-violation"))
                .andExpect(status().isForbidden())
                .andExpect(header().string("Content-Type", MediaType.APPLICATION_PROBLEM_JSON_VALUE))
                .andExpect(jsonPath("$.type").value("https://ospysin.dev/errors/policy-violation"))
                .andExpect(jsonPath("$.title").value("Policy Engine Rejection"))
                .andExpect(jsonPath("$.status").value(403))
                .andExpect(jsonPath("$.detail").value("Target resolves to private network 192.168.1.100 while session is in PUBLIC mode."))
                .andExpect(jsonPath("$.invalidParams[0].name").value("targetUrl"))
                .andExpect(jsonPath("$.invalidParams[0].reason").value("Resolves to prohibited special-purpose IP range."))
                .andExpect(jsonPath("$.timestamp").value("2026-10-13T20:00:00Z"));
    }

    @Test
    @DisplayName("Returns 404 Not Found on ResourceNotFoundException")
    void shouldReturn404OnResourceNotFound() throws Exception {
        mockMvc.perform(get("/test/not-found"))
                .andExpect(status().isNotFound())
                .andExpect(header().string("Content-Type", MediaType.APPLICATION_PROBLEM_JSON_VALUE))
                .andExpect(jsonPath("$.type").value("https://ospysin.dev/errors/resource-not-found"))
                .andExpect(jsonPath("$.title").value("Resource Not Found"))
                .andExpect(jsonPath("$.status").value(404))
                .andExpect(jsonPath("$.detail").value("Entity with id 123 was not found"));
    }

    @Test
    @DisplayName("Returns 409 Conflict on ConflictException")
    void shouldReturn409OnConflict() throws Exception {
        mockMvc.perform(get("/test/conflict"))
                .andExpect(status().isConflict())
                .andExpect(header().string("Content-Type", MediaType.APPLICATION_PROBLEM_JSON_VALUE))
                .andExpect(jsonPath("$.type").value("https://ospysin.dev/errors/conflict"))
                .andExpect(jsonPath("$.title").value("Conflict"))
                .andExpect(jsonPath("$.status").value(409));
    }

    @Test
    @DisplayName("Returns 400 Bad Request on malformed JSON payload")
    void shouldReturn400OnMalformedJson() throws Exception {
        String malformedJson = "{ \"username\": ";

        mockMvc.perform(post("/test/validate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(malformedJson))
                .andExpect(status().isBadRequest())
                .andExpect(header().string("Content-Type", MediaType.APPLICATION_PROBLEM_JSON_VALUE))
                .andExpect(jsonPath("$.type").value("https://ospysin.dev/errors/bad-request"))
                .andExpect(jsonPath("$.title").value("Bad Request"))
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.detail").value("Malformed JSON request body or unreadable input."))
                .andExpect(jsonPath("$.instance").value("/test/validate"))
                .andExpect(jsonPath("$.timestamp").value("2026-10-13T20:00:00Z"));
    }

    @Test
    @DisplayName("Returns 400 Bad Request on parameter type mismatch")
    void shouldReturn400OnParameterTypeMismatch() throws Exception {
        mockMvc.perform(get("/test/param/not-a-valid-uuid"))
                .andExpect(status().isBadRequest())
                .andExpect(header().string("Content-Type", MediaType.APPLICATION_PROBLEM_JSON_VALUE))
                .andExpect(jsonPath("$.type").value("https://ospysin.dev/errors/bad-request"))
                .andExpect(jsonPath("$.title").value("Bad Request"))
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.detail").value("Invalid value for parameter 'id'."))
                .andExpect(jsonPath("$.instance").value("/test/param/not-a-valid-uuid"))
                .andExpect(jsonPath("$.timestamp").value("2026-10-13T20:00:00Z"));
    }

    @Test
    @DisplayName("Returns 500 Internal Server Error without leaking internal stack trace or SQL details")
    void shouldReturn500WithoutLeakingInternalDetails() throws Exception {
        mockMvc.perform(get("/test/internal-error"))
                .andExpect(status().isInternalServerError())
                .andExpect(header().string("Content-Type", MediaType.APPLICATION_PROBLEM_JSON_VALUE))
                .andExpect(jsonPath("$.type").value("https://ospysin.dev/errors/internal-error"))
                .andExpect(jsonPath("$.title").value("Internal Server Error"))
                .andExpect(jsonPath("$.status").value(500))
                .andExpect(jsonPath("$.detail", not(containsString("SELECT * FROM secrets"))))
                .andExpect(jsonPath("$.detail").value("An unexpected internal error occurred. Please consult server administrator logs."));
    }

    @Test
    @DisplayName("Returns 406 Not Acceptable on HttpMediaTypeNotAcceptableException")
    void shouldReturn406OnMediaTypeNotAcceptable() throws Exception {
        mockMvc.perform(get("/test/media-not-acceptable"))
                .andExpect(status().isNotAcceptable())
                .andExpect(header().string("Content-Type", MediaType.APPLICATION_PROBLEM_JSON_VALUE))
                .andExpect(jsonPath("$.type").value("https://ospysin.dev/errors/not-acceptable"))
                .andExpect(jsonPath("$.title").value("Not Acceptable"))
                .andExpect(jsonPath("$.status").value(406));
    }

    @Test
    @DisplayName("Returns 204 No Content on AsyncRequestTimeoutException without logging 500")
    void shouldReturn204OnAsyncRequestTimeout() throws Exception {
        mockMvc.perform(get("/test/async-timeout"))
                .andExpect(status().isNoContent());
    }
}
