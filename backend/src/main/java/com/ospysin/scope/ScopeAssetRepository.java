package com.ospysin.scope;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface ScopeAssetRepository extends JpaRepository<ScopeAsset, UUID> {

    List<ScopeAsset> findByEngagementId(UUID engagementId);
}
