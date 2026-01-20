package com.adityachandel.booklore.repository;

import com.adityachandel.booklore.model.entity.APIKeyEntity;
import com.adityachandel.booklore.model.entity.BookLoreUserEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/**
 * Repository for managing API Key entities.
 */
@Repository
public interface APIKeyRepository extends JpaRepository<APIKeyEntity, Long> {

    /**
     * Find an API key by its hash
     */
    Optional<APIKeyEntity> findByKeyHash(String keyHash);

    /**
     * Find API keys by key prefix (for efficient authentication lookup)
     */
    List<APIKeyEntity> findByKeyPrefixAndIsActiveTrue(String keyPrefix);

    /**
     * Find all API keys for a specific user
     */
    List<APIKeyEntity> findByUserOrderByCreatedAtDesc(BookLoreUserEntity user);

    /**
     * Find all active API keys for a specific user
     */
    @Query("SELECT a FROM APIKeyEntity a WHERE a.user = :user AND a.isActive = true AND (a.expiresAt IS NULL OR a.expiresAt > CURRENT_TIMESTAMP) AND a.revokedAt IS NULL ORDER BY a.createdAt DESC")
    List<APIKeyEntity> findActiveKeysByUser(@Param("user") BookLoreUserEntity user);

    /**
     * Find an API key by ID and user (to verify ownership)
     */
    Optional<APIKeyEntity> findByIdAndUser(Long id, BookLoreUserEntity user);

    /**
     * Check if a user has an API key with a given name
     */
    boolean existsByUserAndNameIgnoreCase(BookLoreUserEntity user, String name);

    /**
     * Delete all API keys for a specific user
     */
    void deleteByUser(BookLoreUserEntity user);

    /**
     * Count active API keys for a user
     */
    @Query("SELECT COUNT(a) FROM APIKeyEntity a WHERE a.user = :user AND a.isActive = true AND (a.expiresAt IS NULL OR a.expiresAt > CURRENT_TIMESTAMP) AND a.revokedAt IS NULL")
    long countActiveKeysByUser(@Param("user") BookLoreUserEntity user);
}
