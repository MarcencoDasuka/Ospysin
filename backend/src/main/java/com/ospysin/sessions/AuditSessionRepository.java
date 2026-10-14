package com.ospysin.sessions;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface AuditSessionRepository extends JpaRepository<AuditSession, UUID> {

    List<AuditSession> findByEngagementId(UUID engagementId);

    Page<AuditSession> findAllByOrderByCreatedAtDesc(Pageable pageable);
}
