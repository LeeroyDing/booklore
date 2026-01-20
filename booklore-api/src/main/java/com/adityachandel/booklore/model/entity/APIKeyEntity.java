package com.adityachandel.booklore.model.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

/**
 * Entity representing API Keys for programmatic access to BookLore API.
 * API keys are hashed before storage for security purposes.
 */
@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "api_keys", uniqueConstraints = {
        @UniqueConstraint(columnNames = "key_hash", name = "uk_api_keys_key_hash")
})
public class APIKeyEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "user_id", nullable = false)
    private BookLoreUserEntity user;

    @Column(name = "key_hash", nullable = false, unique = true, length = 255)
    private String keyHash;

    /**
     * First 12 characters of the API key (unencrypted) for efficient lookup
     * Reduces the number of hash comparisons needed during authentication
     */
    @Column(name = "key_prefix", nullable = false, unique = true, length = 20)
    private String keyPrefix;

    @Column(name = "name", nullable = false)
    private String name;

    @Column(name = "description")
    private String description;

    @Column(name = "is_active", nullable = false)
    @Builder.Default
    private boolean isActive = true;

    @Column(name = "last_used_at")
    private LocalDateTime lastUsedAt;

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "expires_at")
    private LocalDateTime expiresAt;

    /**
     * Revoke timestamp - when the key was revoked (if applicable)
     */
    @Column(name = "revoked_at")
    private LocalDateTime revokedAt;

    @PrePersist
    protected void onCreate() {
        if (createdAt == null) {
            createdAt = LocalDateTime.now();
        }
        if (isActive) {
            revokedAt = null;
        }
    }

    /**
     * Check if the API key is valid (active, not expired, not revoked)
     */
    public boolean isValid() {
        if (!isActive || revokedAt != null) {
            return false;
        }
        if (expiresAt != null && LocalDateTime.now().isAfter(expiresAt)) {
            return false;
        }
        return true;
    }

    /**
     * Mark this API key as used
     */
    public void recordUsage() {
        this.lastUsedAt = LocalDateTime.now();
    }

    /**
     * Revoke this API key
     */
    public void revoke() {
        this.isActive = false;
        this.revokedAt = LocalDateTime.now();
    }
}
