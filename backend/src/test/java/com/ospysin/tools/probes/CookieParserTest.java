package com.ospysin.tools.probes;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class CookieParserTest {

    @Test
    @DisplayName("Parse complete Set-Cookie header with all standard security attributes")
    void parseFullCookie() {
        String header = "SESSIONID=abc123xyz; Path=/; Domain=example.com; Secure; HttpOnly; SameSite=Strict";
        ParsedCookie cookie = CookieParser.parse(header);

        assertThat(cookie).isNotNull();
        assertThat(cookie.name()).isEqualTo("SESSIONID");
        assertThat(cookie.value()).isEqualTo("abc123xyz");
        assertThat(cookie.path()).isEqualTo("/");
        assertThat(cookie.domain()).isEqualTo("example.com");
        assertThat(cookie.secure()).isTrue();
        assertThat(cookie.httpOnly()).isTrue();
        assertThat(cookie.sameSite()).isEqualTo("Strict");

        Map<String, Object> map = cookie.toMap();
        assertThat(map).containsEntry("name", "SESSIONID")
                .containsEntry("secure", true)
                .containsEntry("httpOnly", true)
                .containsEntry("sameSite", "Strict")
                .containsEntry("path", "/")
                .containsEntry("domain", "example.com");
    }

    @Test
    @DisplayName("Parse insecure cookie missing HttpOnly, Secure, and SameSite")
    void parseInsecureCookie() {
        String header = "tracker_id=12345";
        ParsedCookie cookie = CookieParser.parse(header);

        assertThat(cookie).isNotNull();
        assertThat(cookie.name()).isEqualTo("tracker_id");
        assertThat(cookie.value()).isEqualTo("12345");
        assertThat(cookie.secure()).isFalse();
        assertThat(cookie.httpOnly()).isFalse();
        assertThat(cookie.sameSite()).isNull();
        assertThat(cookie.path()).isNull();
        assertThat(cookie.domain()).isNull();
    }

    @Test
    @DisplayName("Parse quoted attributes and case-insensitive flags")
    void parseQuotedAndCaseInsensitiveAttributes() {
        String header = "test=val; path=\"/app\"; domain=\"sub.example.com\"; SECURE; HTTPONLY; samesite=lax";
        ParsedCookie cookie = CookieParser.parse(header);

        assertThat(cookie).isNotNull();
        assertThat(cookie.name()).isEqualTo("test");
        assertThat(cookie.value()).isEqualTo("val");
        assertThat(cookie.path()).isEqualTo("/app");
        assertThat(cookie.domain()).isEqualTo("sub.example.com");
        assertThat(cookie.secure()).isTrue();
        assertThat(cookie.httpOnly()).isTrue();
        assertThat(cookie.sameSite()).isEqualTo("lax");
    }

    @Test
    @DisplayName("Parse empty value, deleted cookies, or cookie without equals")
    void parseEmptyValueOrNoEquals() {
        ParsedCookie deleted = CookieParser.parse("deleted=; Max-Age=0; Path=/");
        assertThat(deleted).isNotNull();
        assertThat(deleted.name()).isEqualTo("deleted");
        assertThat(deleted.value()).isEmpty();
        assertThat(deleted.path()).isEqualTo("/");

        ParsedCookie noEquals = CookieParser.parse("FLAG_ONLY; Secure");
        assertThat(noEquals).isNotNull();
        assertThat(noEquals.name()).isEqualTo("FLAG_ONLY");
        assertThat(noEquals.value()).isEmpty();
        assertThat(noEquals.secure()).isTrue();
    }

    @Test
    @DisplayName("Return null on null, blank, or malformed header")
    void parseInvalidReturnsNull() {
        assertThat(CookieParser.parse(null)).isNull();
        assertThat(CookieParser.parse("")).isNull();
        assertThat(CookieParser.parse("   ")).isNull();
        assertThat(CookieParser.parse(";;;")).isNull();
    }
}
