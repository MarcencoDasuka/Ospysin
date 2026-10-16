package com.ospysin.findings;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Collection;
import java.util.List;
import java.util.UUID;

@Repository
public interface FindingRepository extends JpaRepository<Finding, UUID> {

    List<Finding> findBySessionId(UUID sessionId);

    List<Finding> findBySessionIdOrderByCreatedAtAsc(UUID sessionId);

    java.util.Optional<Finding> findByIdAndSessionId(UUID id, UUID sessionId);

    List<Finding> findBySessionIdAndStatusNot(UUID sessionId, FindingStatus excludedStatus);

    long countBySessionId(UUID sessionId);

    long countBySessionIdAndStatusNot(UUID sessionId, FindingStatus excludedStatus);

    long countBySessionIdAndStatusNotIn(UUID sessionId, Collection<FindingStatus> excludedStatuses);

    @Query("SELECT f.session.id, COUNT(f) FROM Finding f WHERE f.session.id IN :sessionIds AND f.status NOT IN (com.ospysin.findings.FindingStatus.REJECTED, com.ospysin.findings.FindingStatus.FALSE_POSITIVE) GROUP BY f.session.id")
    List<Object[]> countFindingsBySessionIds(@Param("sessionIds") Collection<UUID> sessionIds);
}
