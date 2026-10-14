package com.ospysin.execution;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

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
}
