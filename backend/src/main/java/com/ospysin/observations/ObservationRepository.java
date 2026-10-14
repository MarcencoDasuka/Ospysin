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

    @Query("SELECT r.execution.id, COUNT(o) FROM Observation o JOIN o.result r WHERE r.execution.id IN :executionIds GROUP BY r.execution.id")
    List<Object[]> countObservationsByExecutionIds(@Param("executionIds") Collection<UUID> executionIds);
}
