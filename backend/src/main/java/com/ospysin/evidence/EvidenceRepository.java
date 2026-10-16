package com.ospysin.evidence;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Collection;
import java.util.List;
import java.util.UUID;

@Repository
public interface EvidenceRepository extends JpaRepository<Evidence, UUID> {

    List<Evidence> findByFindingId(UUID findingId);

    List<Evidence> findByFindingIdOrderByCreatedAtAsc(UUID findingId);

    @Query("SELECT e FROM Evidence e JOIN FETCH e.result r JOIN FETCH r.execution ex WHERE e.finding.id IN :findingIds ORDER BY e.createdAt ASC")
    List<Evidence> findByFindingIdInOrderByCreatedAtAsc(@Param("findingIds") Collection<UUID> findingIds);
}
