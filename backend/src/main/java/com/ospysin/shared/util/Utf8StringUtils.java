package com.ospysin.shared.util;

import java.nio.charset.StandardCharsets;

/**
 * Utility for safe UTF-8 string truncation ensuring byte boundaries and surrogate integrity.
 */
public final class Utf8StringUtils {

    public static final int MAX_RAW_OUTPUT_BYTES = 1_048_576; // 1 MB cap for tool_results.raw_output

    private Utf8StringUtils() {
        // Non-instantiable utility
    }

    /**
     * Safely truncates a string so that its UTF-8 encoded byte representation does not exceed {@code maxBytes}.
     * Ensures Unicode code points and surrogate pairs are not broken at the boundary.
     *
     * @param input the input string to truncate (may be null)
     * @param maxBytes the maximum allowed UTF-8 byte length (must be >= 0)
     * @return the truncated string whose UTF-8 byte length is &lt;= maxBytes, or null if input was null
     */
    public static String truncateUtf8(String input, int maxBytes) {
        if (input == null) {
            return null;
        }
        if (maxBytes <= 0) {
            return "";
        }

        byte[] originalBytes = input.getBytes(StandardCharsets.UTF_8);
        if (originalBytes.length <= maxBytes) {
            return input;
        }

        int currentByteCount = 0;
        int charIndex = 0;
        int length = input.length();

        while (charIndex < length) {
            int codePoint = input.codePointAt(charIndex);
            int charCount = Character.charCount(codePoint);
            int codePointBytes = getCodePointByteLength(codePoint);

            if (currentByteCount + codePointBytes > maxBytes) {
                break;
            }

            currentByteCount += codePointBytes;
            charIndex += charCount;
        }

        return input.substring(0, charIndex);
    }

    private static int getCodePointByteLength(int codePoint) {
        if (codePoint <= 0x7F) {
            return 1;
        } else if (codePoint <= 0x7FF) {
            return 2;
        } else if (codePoint <= 0xFFFF) {
            return 3;
        } else {
            return 4;
        }
    }
}
