package com.ospysin.tools;

import com.ospysin.AbstractIntegrationTest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@AutoConfigureMockMvc
class ToolCatalogControllerIT extends AbstractIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @WithMockUser(username = "auditor", roles = {"AUDITOR"})
    @DisplayName("GET /api/tools returns 200 OK with all 15 canonical tools across 3 tiers")
    void listToolsReturnsAll15Tools() throws Exception {
        mockMvc.perform(get("/api/tools")
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(15)))
                // Verify all 15 IDs exist
                .andExpect(jsonPath("$[*].id", containsInAnyOrder(
                        "dns_lookup",
                        "whois_lookup",
                        "tls_info",
                        "http_headers",
                        "robots_txt",
                        "sitemap_xml",
                        "extract_links",
                        "extract_js_urls",
                        "tech_detect",
                        "sensitive_files_check",
                        "js_secrets_scanner",
                        "cors_misconfig_check",
                        "subdomain_takeover_check",
                        "security_headers_score",
                        "cve_matcher"
                )))
                // Verify specific tier items
                .andExpect(jsonPath("$[?(@.id == 'dns_lookup')].executionType").value(hasItem("THIRD_PARTY_RECON")))
                .andExpect(jsonPath("$[?(@.id == 'whois_lookup')].executionType").value(hasItem("THIRD_PARTY_RECON")))
                .andExpect(jsonPath("$[?(@.id == 'http_headers')].executionType").value(hasItem("DIRECT_TARGET_PROBE")))
                .andExpect(jsonPath("$[?(@.id == 'tls_info')].executionType").value(hasItem("DIRECT_TARGET_PROBE")))
                .andExpect(jsonPath("$[?(@.id == 'security_headers_score')].executionType").value(hasItem("OFFLINE_ANALYSIS")))
                .andExpect(jsonPath("$[?(@.id == 'cve_matcher')].executionType").value(hasItem("OFFLINE_ANALYSIS")))
                // Verify inputSchema is present on each tool
                .andExpect(jsonPath("$[?(@.id == 'dns_lookup')].inputSchema.recordTypes").exists())
                .andExpect(jsonPath("$[?(@.id == 'http_headers')].inputSchema.followRedirects").value(false));
    }

    @Test
    @DisplayName("GET /api/tools unauthenticated returns 401 Unauthorized ProblemDetail")
    void listToolsUnauthenticated() throws Exception {
        mockMvc.perform(get("/api/tools")
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string("Content-Type", containsString("application/problem+json")))
                .andExpect(jsonPath("$.type").value("https://ospysin.dev/errors/unauthorized"))
                .andExpect(jsonPath("$.status").value(401));
    }
}
