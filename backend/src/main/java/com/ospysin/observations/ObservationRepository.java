package com.ospysin.observations;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Collection;
import java.util.List;
import java.util.UUID;

@Repository
public interface ObservationRepository extends JpaRepository<Observation, UUID> {

    List<Observation> findByResultId(UUID resultId);

    @Query("SELECT o FROM Observation o WHERE o.result.execution.id = :executionId ORDER BY o.detectedAt ASC")
    List<Observation> findByExecutionIdOrderByDetectedAtAsc(@Param("executionId") UUID executionId);

    @Query("SELECT o FROM Observation o JOIN FETCH o.result r JOIN FETCH r.execution e WHERE e.session.id = :sessionId ORDER BY o.detectedAt ASC")
    List<Observation> findBySessionIdOrderByDetectedAtAsc(@Param("sessionId") UUID sessionId);

    @Query("SELECT r.execution.id, COUNT(o) FROM Observation o JOIN o.result r WHERE r.execution.id IN :executionIds GROUP BY r.execution.id")
    List<Object[]> countObservationsByExecutionIds(@Param("executionIds") Collection<UUID> executionIds);
}
