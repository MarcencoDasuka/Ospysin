package com.ospysin.findings;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface FindingRepository extends JpaRepository<Finding, UUID> {

    List<Finding> findBySessionId(UUID sessionId);

    List<Finding> findBySessionIdAndStatusNot(UUID sessionId, FindingStatus excludedStatus);
}
