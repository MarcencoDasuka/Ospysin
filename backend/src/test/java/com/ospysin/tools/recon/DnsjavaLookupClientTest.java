package com.ospysin.tools.recon;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class DnsjavaLookupClientTest {

    @Test
    @DisplayName("DnsjavaLookupClient handles blank or invalid queries gracefully")
    void handlesBlankOrInvalidQueries() throws Exception {
        DnsjavaLookupClient client = new DnsjavaLookupClient();

        assertThat(client.queryRecords(null, "A")).isEmpty();
        assertThat(client.queryRecords("example.com", null)).isEmpty();
        assertThat(client.queryRecords("", "A")).isEmpty();
        assertThat(client.queryRecords("example.com", "")).isEmpty();
        assertThat(client.queryRecords("example.com", "NOT_A_REAL_DNS_TYPE_999")).isEmpty();
        assertThat(client.queryRecords("illegal..domain...", "A")).isEmpty();
    }
}
