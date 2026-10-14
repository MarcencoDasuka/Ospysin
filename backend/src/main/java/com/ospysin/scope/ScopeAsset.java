package com.ospysin.scope;

import com.ospysin.engagements.Engagement;
import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "scope_assets")
@org.hibernate.annotations.Immutable
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class ScopeAsset {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "engagement_id", nullable = false)
    private Engagement engagement;

    @Enumerated(EnumType.STRING)
    @Column(name = "asset_type", nullable = false, length = 20)
    private AssetType assetType;

    @Column(name = "value", nullable = false, length = 255)
    private String value;

    @Column(name = "is_wildcard", nullable = false)
    private boolean isWildcard;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Builder
    private ScopeAsset(Engagement engagement, AssetType assetType, String value, Boolean isWildcard, Instant createdAt) {
        this.engagement = engagement;
        this.assetType = assetType;
        this.value = value;
        this.isWildcard = isWildcard != null ? isWildcard : false;
        this.createdAt = createdAt != null ? createdAt : Instant.now();
    }
}
