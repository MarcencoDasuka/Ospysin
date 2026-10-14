package com.ospysin.sessions;

import jakarta.persistence.LockModeType;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface AuditSessionRepository extends JpaRepository<AuditSession, UUID> {

    List<AuditSession> findByEngagementId(UUID engagementId);

    Page<AuditSession> findAllByOrderByCreatedAtDesc(Pageable pageable);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT s FROM AuditSession s WHERE s.id = :id")
    Optional<AuditSession> findByIdForUpdate(@Param("id") UUID id);
}

