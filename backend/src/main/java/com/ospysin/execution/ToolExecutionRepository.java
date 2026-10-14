package com.ospysin.execution;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

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
}
