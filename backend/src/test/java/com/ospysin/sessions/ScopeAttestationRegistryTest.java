package com.ospysin.sessions;

import com.ospysin.shared.error.ValidationException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ScopeAttestationRegistryTest {

    private ScopeAttestationRegistry registry;

    @BeforeEach
    void setUp() {
        registry = new ScopeAttestationRegistry();
    }

    @Test
    @DisplayName("validate() succeeds for canonical version 1.0.0 and scopeAcknowledged true")
    void validateSuccess() {
        registry.validate(true, "1.0.0");
    }

    @Test
    @DisplayName("validate() rejects false or null scopeAcknowledged with 422 invalidParams")
    void validateRejectsUnacknowledgedScope() {
        assertThatThrownBy(() -> registry.validate(false, "1.0.0"))
                .isInstanceOf(ValidationException.class)
                .satisfies(ex -> {
                    ValidationException ve = (ValidationException) ex;
                    assertThat(ve.getInvalidParams()).hasSize(1);
                    assertThat(ve.getInvalidParams().get(0).name()).isEqualTo("scopeAcknowledged");
                });

        assertThatThrownBy(() -> registry.validate(null, "1.0.0"))
                .isInstanceOf(ValidationException.class)
                .satisfies(ex -> {
                    ValidationException ve = (ValidationException) ex;
                    assertThat(ve.getInvalidParams()).hasSize(1);
                    assertThat(ve.getInvalidParams().get(0).name()).isEqualTo("scopeAcknowledged");
                });
    }

    @Test
    @DisplayName("validate() rejects unsupported statement version with invalidParams")
    void validateRejectsUnsupportedVersion() {
        assertThatThrownBy(() -> registry.validate(true, "2.0.0"))
                .isInstanceOf(ValidationException.class)
                .satisfies(ex -> {
                    ValidationException ve = (ValidationException) ex;
                    assertThat(ve.getInvalidParams()).hasSize(1);
                    assertThat(ve.getInvalidParams().get(0).name()).isEqualTo("scopeAckVersion");
                });

        assertThatThrownBy(() -> registry.validate(true, null))
                .isInstanceOf(ValidationException.class)
                .satisfies(ex -> {
                    ValidationException ve = (ValidationException) ex;
                    assertThat(ve.getInvalidParams()).hasSize(1);
                    assertThat(ve.getInvalidParams().get(0).name()).isEqualTo("scopeAckVersion");
                });
    }

    @Test
    @DisplayName("validate() aggregates multiple invalid parameters when both are invalid")
    void validateAggregatesMultipleErrors() {
        assertThatThrownBy(() -> registry.validate(false, "9.9.9"))
                .isInstanceOf(ValidationException.class)
                .satisfies(ex -> {
                    ValidationException ve = (ValidationException) ex;
                    assertThat(ve.getInvalidParams()).hasSize(2);
                    assertThat(ve.getInvalidParams()).extracting("name")
                            .containsExactlyInAnyOrder("scopeAcknowledged", "scopeAckVersion");
                });
    }

    @Test
    @DisplayName("computeDigest() generates deterministic 64-char lowercase hex SHA-256")
    void computeDigestGeneratesValidSha256() throws Exception {
        String text = ScopeAttestationRegistry.STATEMENT_V1;
        String digest = registry.computeDigest(text);

        assertThat(digest).hasSize(64);
        assertThat(digest).matches("^[0-9a-f]{64}$");

        MessageDigest md = MessageDigest.getInstance("SHA-256");
        String expected = HexFormat.of().formatHex(md.digest(text.getBytes(StandardCharsets.UTF_8)));
        assertThat(digest).isEqualTo(expected);
    }

    @Test
    @DisplayName("getStatement() returns canonical statement for version 1.0.0 and throws for unknown")
    void getStatementRetrieval() {
        assertThat(registry.getStatement("1.0.0")).isEqualTo(ScopeAttestationRegistry.STATEMENT_V1);

        assertThatThrownBy(() -> registry.getStatement("unknown"))
                .isInstanceOf(ValidationException.class);
    }
}
