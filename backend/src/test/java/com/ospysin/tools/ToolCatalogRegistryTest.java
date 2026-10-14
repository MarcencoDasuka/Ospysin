package com.ospysin.tools;

import com.ospysin.shared.error.InvalidParam;
import com.ospysin.shared.error.ValidationException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ToolCatalogRegistryTest {

    private ToolCatalogRegistry registry;

    @BeforeEach
    void setUp() {
        registry = new ToolCatalogRegistry(Collections.emptyList());
    }

    @Test
    @DisplayName("Registry contains exactly 15 canonical tools with immutable metadata")
    void registryContains15CanonicalTools() {
        List<ToolMetadata> tools = registry.getAllTools();
        assertThat(tools).hasSize(15);

        Optional<ToolMetadata> httpHeaders = registry.findMetadata("http_headers");
        assertThat(httpHeaders).isPresent();
        assertThat(httpHeaders.get().name()).isEqualTo("HTTP Headers & Cookies");
        assertThat(httpHeaders.get().category()).isEqualTo("HTTP");
        assertThat(httpHeaders.get().executionType()).isEqualTo(ExecutionType.DIRECT_TARGET_PROBE);
        assertThat(httpHeaders.get().inputSchema()).containsKey("followRedirects");

        assertThat(registry.findMetadata("non_existent")).isEmpty();
        assertThat(registry.findMetadata(null)).isEmpty();
        assertThat(registry.isRegistered("http_headers")).isTrue();
        assertThat(registry.isRegistered("fake_tool")).isFalse();
        assertThat(registry.isRegistered(null)).isFalse();
    }

    @Test
    @DisplayName("validateParams accepts valid parameters or empty params")
    void validateParamsValid() {
        registry.validateParams("http_headers", Map.of("customPort", 8080, "followRedirects", true));
        registry.validateParams("http_headers", Collections.emptyMap());
        registry.validateParams("sitemap_xml", Map.of("maxUrls", 200, "customPath", "/sitemap.xml"));
        registry.validateParams("security_headers_score", Map.of("stepId", "00000000-0000-0000-0000-000000000001"));
    }

    @Test
    @DisplayName("validateParams throws IllegalArgumentException on unknown tool ID")
    void validateParamsUnknownTool() {
        assertThatThrownBy(() -> registry.validateParams("unknown_tool", Map.of()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Unknown tool ID");
    }

    @Test
    @DisplayName("validateParams throws ValidationException when customPort is out of range 1..65535")
    void validateParamsInvalidPort() {
        assertThatThrownBy(() -> registry.validateParams("http_headers", Map.of("customPort", 70000)))
                .isInstanceOf(ValidationException.class)
                .satisfies(ex -> {
                    ValidationException ve = (ValidationException) ex;
                    assertThat(ve.getInvalidParams()).hasSize(1);
                    InvalidParam param = ve.getInvalidParams().get(0);
                    assertThat(param.name()).isEqualTo("customPort");
                });

        assertThatThrownBy(() -> registry.validateParams("http_headers", Map.of("customPort", 0)))
                .isInstanceOf(ValidationException.class);
    }

    @Test
    @DisplayName("validateParams throws ValidationException when stepId is not a valid UUID")
    void validateParamsInvalidStepId() {
        assertThatThrownBy(() -> registry.validateParams("security_headers_score", Map.of("stepId", "not-a-valid-uuid")))
                .isInstanceOf(ValidationException.class)
                .satisfies(ex -> {
                    ValidationException ve = (ValidationException) ex;
                    assertThat(ve.getInvalidParams()).extracting(InvalidParam::name).contains("stepId");
                });
    }

    @Test
    @DisplayName("validateParams throws ValidationException when maxUrls is out of range")
    void validateParamsInvalidMaxUrls() {
        assertThatThrownBy(() -> registry.validateParams("sitemap_xml", Map.of("maxUrls", -5)))
                .isInstanceOf(ValidationException.class);

        assertThatThrownBy(() -> registry.validateParams("sitemap_xml", Map.of("maxUrls", 50000)))
                .isInstanceOf(ValidationException.class);
    }

    @Test
    @DisplayName("validateParams delegates to registered OspysinTool bean")
    void validateParamsDelegatesToToolBean() {
        OspysinTool customTool = new OspysinTool() {
            @Override
            public String getToolId() {
                return "dns_lookup";
            }

            @Override
            public void validateParams(Map<String, Object> params) {
                if (params.containsKey("bad")) {
                    throw new ValidationException("bad parameter", List.of(new InvalidParam("bad", "Bad value")));
                }
            }

            @Override
            public ToolExecutionOutcome execute(ToolExecutionContext context) {
                return null;
            }
        };

        registry.registerToolBean(customTool);
        assertThat(registry.getTool("dns_lookup")).isPresent();

        assertThatThrownBy(() -> registry.validateParams("dns_lookup", Map.of("bad", "value")))
                .isInstanceOf(ValidationException.class)
                .satisfies(ex -> {
                    ValidationException ve = (ValidationException) ex;
                    assertThat(ve.getInvalidParams()).extracting(InvalidParam::name).contains("bad");
                });
    }

    @Test
    @DisplayName("validateParams rejects floating-point numbers and Long overflow in integer fields")
    void validateParamsRejectsInvalidNumericTypes() {
        // Floating point in integer field customPort
        assertThatThrownBy(() -> registry.validateParams("http_headers", Map.of("customPort", 80.5)))
                .isInstanceOf(ValidationException.class)
                .satisfies(ex -> {
                    ValidationException ve = (ValidationException) ex;
                    assertThat(ve.getInvalidParams()).extracting(InvalidParam::name).contains("customPort");
                });

        // Long overflow (e.g. 4294967376L) in integer field customPort
        assertThatThrownBy(() -> registry.validateParams("http_headers", Map.of("customPort", 4294967376L)))
                .isInstanceOf(ValidationException.class)
                .satisfies(ex -> {
                    ValidationException ve = (ValidationException) ex;
                    assertThat(ve.getInvalidParams()).extracting(InvalidParam::name).contains("customPort");
                });
    }

    @Test
    @DisplayName("validateParams requires stepId for security_headers_score and cve_matcher")
    void validateParamsRequiresStepId() {
        assertThatThrownBy(() -> registry.validateParams("security_headers_score", Map.of()))
                .isInstanceOf(ValidationException.class)
                .satisfies(ex -> {
                    ValidationException ve = (ValidationException) ex;
                    assertThat(ve.getInvalidParams()).extracting(InvalidParam::name).contains("stepId");
                });

        assertThatThrownBy(() -> registry.validateParams("cve_matcher", Collections.emptyMap()))
                .isInstanceOf(ValidationException.class)
                .satisfies(ex -> {
                    ValidationException ve = (ValidationException) ex;
                    assertThat(ve.getInvalidParams()).extracting(InvalidParam::name).contains("stepId");
                });
    }

    @Test
    @DisplayName("validateParams rejects non-list for customPaths in sensitive_files_check")
    void validateParamsRejectsNonListForArrayParam() {
        assertThatThrownBy(() -> registry.validateParams("sensitive_files_check", Map.of("customPaths", "/not-a-list")))
                .isInstanceOf(ValidationException.class)
                .satisfies(ex -> {
                    ValidationException ve = (ValidationException) ex;
                    assertThat(ve.getInvalidParams()).extracting(InvalidParam::name).contains("customPaths");
                });
    }
}
