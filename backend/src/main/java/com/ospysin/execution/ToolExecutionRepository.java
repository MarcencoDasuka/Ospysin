package com.ospysin.execution;

import jakarta.persistence.LockModeType;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface ToolExecutionRepository extends JpaRepository<ToolExecution, UUID> {

    List<ToolExecution> findBySessionIdOrderByCreatedAtAsc(UUID sessionId);

    Optional<ToolExecution> findBySessionIdAndToolIdAndStatusIn(
            UUID sessionId,
            String toolId,
            List<ExecutionStatus> statuses
    );

    long countBySessionId(UUID sessionId);

    boolean existsBySessionIdAndStatusIn(UUID sessionId, Collection<ExecutionStatus> statuses);

    List<ToolExecution> findBySessionIdAndStatusIn(UUID sessionId, Collection<ExecutionStatus> statuses);

    @Query("SELECT e.session.id, COUNT(e) FROM ToolExecution e WHERE e.session.id IN :sessionIds GROUP BY e.session.id")
    List<Object[]> countExecutionsBySessionIds(@Param("sessionIds") Collection<UUID> sessionIds);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT e FROM ToolExecution e WHERE e.id = :id")
    Optional<ToolExecution> findByIdForUpdate(@Param("id") UUID id);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT e FROM ToolExecution e WHERE e.status = :status AND e.leaseExpiresAt < :now")
    List<ToolExecution> findExpiredLeasesForUpdate(@Param("status") ExecutionStatus status, @Param("now") Instant now);

    @Query("""
        SELECT e.id FROM ToolExecution e
        WHERE e.status = com.ospysin.execution.ExecutionStatus.PENDING
          AND NOT EXISTS (
              SELECT 1 FROM ToolExecution r
              WHERE r.session.id = e.session.id
                AND r.status = com.ospysin.execution.ExecutionStatus.RUNNING
          )
        ORDER BY e.createdAt ASC
    """)
    List<UUID> findPendingCandidateIds(Pageable pageable);
}
