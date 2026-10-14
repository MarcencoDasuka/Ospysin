package com.ospysin.shared.util;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

class Utf8ByteTruncationTest {

    @Test
    @DisplayName("Returns null when input is null")
    void shouldReturnNullForNullInput() {
        assertThat(Utf8StringUtils.truncateUtf8(null, 100)).isNull();
    }

    @Test
    @DisplayName("Returns empty string when maxBytes is zero or negative")
    void shouldReturnEmptyForZeroOrNegativeMaxBytes() {
        assertThat(Utf8StringUtils.truncateUtf8("hello", 0)).isEmpty();
        assertThat(Utf8StringUtils.truncateUtf8("hello", -5)).isEmpty();
    }

    @Test
    @DisplayName("Does not truncate string if byte length is less than or equal to maxBytes")
    void shouldNotTruncateIfWithinLimit() {
        String input = "Hello, World!";
        int bytes = input.getBytes(StandardCharsets.UTF_8).length;
        assertThat(Utf8StringUtils.truncateUtf8(input, bytes)).isEqualTo(input);
        assertThat(Utf8StringUtils.truncateUtf8(input, bytes + 10)).isEqualTo(input);
    }

    @Test
    @DisplayName("Truncates ASCII string cleanly at maxBytes")
    void shouldTruncateAsciiCleanly() {
        String input = "1234567890";
        String truncated = Utf8StringUtils.truncateUtf8(input, 5);
        assertThat(truncated).isEqualTo("12345");
        assertThat(truncated.getBytes(StandardCharsets.UTF_8).length).isLessThanOrEqualTo(5);
    }

    @Test
    @DisplayName("Does not split multi-byte Cyrillic characters across byte boundary")
    void shouldNotSplitMultiByteCyrillicCharacters() {
        // 'П' is 2 bytes in UTF-8 (0xD0 0x9F), 'р' is 2 bytes (0xD1 0x80)
        String input = "Привет"; // 12 bytes
        // If limit is 3 bytes, only 1 Cyrillic character (2 bytes) fits
        String truncated = Utf8StringUtils.truncateUtf8(input, 3);
        assertThat(truncated).isEqualTo("П");
        assertThat(truncated.getBytes(StandardCharsets.UTF_8).length).isEqualTo(2);

        // If limit is 5 bytes, 'Пр' (4 bytes) fits
        truncated = Utf8StringUtils.truncateUtf8(input, 5);
        assertThat(truncated).isEqualTo("Пр");
        assertThat(truncated.getBytes(StandardCharsets.UTF_8).length).isEqualTo(4);
    }

    @Test
    @DisplayName("Does not split 4-byte UTF-8 emojis or leave dangling surrogate pairs")
    void shouldNotSplitFourByteEmojisOrDanglingSurrogates() {
        // Smiling face with sunglasses '😎' is U+1F60E (4 bytes in UTF-8, 2 chars in Java surrogate pair)
        String emoji = "😎";
        assertThat(emoji.length()).isEqualTo(2);
        assertThat(emoji.getBytes(StandardCharsets.UTF_8).length).isEqualTo(4);

        String input = "ABC" + emoji + "DEF"; // 3 + 4 + 3 = 10 bytes
        // If limit is 6 bytes: 'ABC' (3 bytes) fits, but emoji needs 4 more bytes (total 7 > 6), so only 'ABC' fits
        String truncated = Utf8StringUtils.truncateUtf8(input, 6);
        assertThat(truncated).isEqualTo("ABC");
        assertThat(truncated.getBytes(StandardCharsets.UTF_8).length).isEqualTo(3);

        // If limit is 7 bytes: 'ABC' (3 bytes) + '😎' (4 bytes) = 7 bytes fits exactly
        truncated = Utf8StringUtils.truncateUtf8(input, 7);
        assertThat(truncated).isEqualTo("ABC😎");
        assertThat(truncated.getBytes(StandardCharsets.UTF_8).length).isEqualTo(7);

        // Verify no unpaired surrogates exist in the truncated result
        for (int i = 0; i < truncated.length(); i++) {
            char ch = truncated.charAt(i);
            if (Character.isSurrogate(ch)) {
                // Must be part of a valid pair
                if (Character.isHighSurrogate(ch)) {
                    assertThat(i + 1).isLessThan(truncated.length());
                    assertThat(Character.isLowSurrogate(truncated.charAt(i + 1))).isTrue();
                    i++; // skip low surrogate
                } else {
                    org.junit.jupiter.api.Assertions.fail("Found orphaned low surrogate at position " + i);
                }
            }
        }
    }

    @Test
    @DisplayName("Strictly respects the 1 MB database constraint cap on large mixed payloads")
    void shouldRespectOneMegabyteCapOnMixedPayloads() {
        int cap = Utf8StringUtils.MAX_RAW_OUTPUT_BYTES; // 1_048_576 bytes

        // Build a large string with Cyrillic, 4-byte emojis, and ASCII exceeding 1 MB
        StringBuilder sb = new StringBuilder();
        String chunk = "Log entry: Запрос завершен успешно! Статус: 200 OK. Детализация payload: 😎🚀🛡️ \n";
        while (sb.length() < 1_200_000) {
            sb.append(chunk);
        }

        String largeText = sb.toString();
        assertThat(largeText.getBytes(StandardCharsets.UTF_8).length).isGreaterThan(cap);

        String truncated = Utf8StringUtils.truncateUtf8(largeText, cap);
        byte[] truncatedBytes = truncated.getBytes(StandardCharsets.UTF_8);

        assertThat(truncatedBytes.length).isLessThanOrEqualTo(cap);
        assertThat(truncatedBytes.length).isGreaterThan(cap - 4); // should be within 4 bytes of the limit

        // Verify string round-trip validity
        String roundTrip = new String(truncatedBytes, StandardCharsets.UTF_8);
        assertThat(roundTrip).isEqualTo(truncated);
    }
}
