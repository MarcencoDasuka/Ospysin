package com.ospysin.execution;

import com.ospysin.shared.util.Utf8StringUtils;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.Immutable;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Entity
@Table(name = "tool_results")
@Immutable
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class ToolResult {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @OneToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "execution_id", nullable = false, unique = true)
    private ToolExecution execution;

    @Column(name = "raw_output", nullable = false, columnDefinition = "TEXT")
    private String rawOutput;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "parsed_data", columnDefinition = "jsonb", nullable = false)
    private Map<String, Object> parsedData = new HashMap<>();

    @Column(name = "score")
    private Integer score;

    @Column(name = "has_errors", nullable = false)
    private boolean hasErrors;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Builder
    private ToolResult(ToolExecution execution, String rawOutput, Map<String, Object> parsedData,
                       Integer score, Boolean hasErrors, Instant createdAt) {
        this.execution = execution;
        this.rawOutput = Utf8StringUtils.truncateUtf8(rawOutput, Utf8StringUtils.MAX_RAW_OUTPUT_BYTES);
        this.parsedData = parsedData != null ? new HashMap<>(parsedData) : new HashMap<>();
        this.score = score;
        this.hasErrors = hasErrors != null ? hasErrors : false;
        this.createdAt = createdAt != null ? createdAt : Instant.now();
    }
}
