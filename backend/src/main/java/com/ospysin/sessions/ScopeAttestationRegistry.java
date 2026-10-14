package com.ospysin.sessions;

import com.ospysin.shared.error.InvalidParam;
import com.ospysin.shared.error.ValidationException;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

@Component
public class ScopeAttestationRegistry {

    public static final String CANONICAL_VERSION = "1.0.0";

    public static final String STATEMENT_V1 =
            "I certify under penalty of law that I own this asset or have received explicit, written authorization to conduct security inspection against the target URL. I understand that all actions are forensically recorded in the local immutable audit log.";

    private static final Map<String, String> STATEMENTS = Map.of(
            CANONICAL_VERSION, STATEMENT_V1
    );

    public void validate(Boolean scopeAcknowledged, String scopeAckVersion) {
        List<InvalidParam> invalidParams = new ArrayList<>();

        if (scopeAcknowledged == null || !scopeAcknowledged) {
            invalidParams.add(new InvalidParam(
                    "scopeAcknowledged",
                    "Scope acknowledgment must be explicitly agreed to before session creation"
            ));
        }

        if (scopeAckVersion == null || !STATEMENTS.containsKey(scopeAckVersion)) {
            invalidParams.add(new InvalidParam(
                    "scopeAckVersion",
                    "Unsupported or missing scope acknowledgment statement version. Required: " + CANONICAL_VERSION
            ));
        }

        if (!invalidParams.isEmpty()) {
            throw new ValidationException("Scope attestation failed", invalidParams);
        }
    }

    public String getStatement(String version) {
        String statement = STATEMENTS.get(version);
        if (statement == null) {
            throw new ValidationException(
                    "Unknown scope attestation version: " + version,
                    List.of(new InvalidParam("scopeAckVersion", "Version " + version + " is not recognized"))
            );
        }
        return statement;
    }

    public String computeDigest(String statementText) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(statementText.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 algorithm not available", e);
        }
    }
}
