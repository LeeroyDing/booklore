package com.adityachandel.booklore.config.security.service;

import com.adityachandel.booklore.exception.APIException;
import com.adityachandel.booklore.model.entity.APIKeyEntity;
import com.adityachandel.booklore.model.entity.BookLoreUserEntity;
import com.adityachandel.booklore.model.dto.request.CreateAPIKeyRequest;
import com.adityachandel.booklore.model.dto.response.APIKeyCreatedResponse;
import com.adityachandel.booklore.model.dto.response.APIKeyResponse;
import com.adityachandel.booklore.repository.APIKeyRepository;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Service for managing API Keys
 * Handles generation, validation, and lifecycle management of API keys
 */
@Slf4j
@Service
@AllArgsConstructor
public class APIKeyService {

    private final APIKeyRepository apiKeyRepository;
    private final PasswordEncoder passwordEncoder;

    private static final String API_KEY_PREFIX = "blk_";
    private static final int API_KEY_BYTE_LENGTH = 32;
    private static final int MAX_API_KEYS_PER_USER = 20;

    /**
     * Generate a new API key for a user
     */
    @Transactional
    public APIKeyCreatedResponse generateAPIKey(BookLoreUserEntity user, CreateAPIKeyRequest request) {
        // Validate name uniqueness
        if (apiKeyRepository.existsByUserAndNameIgnoreCase(user, request.getName())) {
            throw new APIException("API key with name '" + request.getName() + "' already exists", HttpStatus.CONFLICT);
        }

        // Check API key limit
        long activeKeyCount = apiKeyRepository.countActiveKeysByUser(user);
        if (activeKeyCount >= MAX_API_KEYS_PER_USER) {
            throw new APIException("Maximum number of API keys (" + MAX_API_KEYS_PER_USER + ") reached", HttpStatus.BAD_REQUEST);
        }

        // Generate the API key
        String plainKey = generatePlainKey();
        String hashedKey = passwordEncoder.encode(plainKey);
        String keyPrefix = plainKey.substring(0, Math.min(12, plainKey.length()));

        // Create the entity
        APIKeyEntity apiKey = APIKeyEntity.builder()
                .user(user)
                .keyHash(hashedKey)
                .keyPrefix(keyPrefix)
                .name(request.getName())
                .description(request.getDescription())
                .expiresAt(request.getExpiresAt())
                .createdAt(LocalDateTime.now())
                .isActive(true)
                .build();

        apiKey = apiKeyRepository.save(apiKey);
        log.info("Generated new API key for user: {}", user.getUsername());

        // Return the response with the plaintext key (only shown once)
        return APIKeyCreatedResponse.builder()
                .id(apiKey.getId())
                .key(plainKey)
                .name(apiKey.getName())
                .description(apiKey.getDescription())
                .expiresAt(apiKey.getExpiresAt())
                .createdAt(apiKey.getCreatedAt())
                .build();
    }

    /**
     * Validate an API key and return the associated user if valid
     * @param plainKey The plaintext API key from the request
     * @return The user associated with the API key, or null if invalid/expired
     */
    public BookLoreUserEntity validateAPIKey(String plainKey) {
        if (plainKey == null || plainKey.isEmpty() || !plainKey.startsWith(API_KEY_PREFIX)) {
            return null;
        }

        try {
            // Extract prefix from the plaintext key for efficient lookup
            String keyPrefix = plainKey.substring(0, Math.min(12, plainKey.length()));

            // Find all active keys with this prefix
            List<APIKeyEntity> candidates = apiKeyRepository.findByKeyPrefixAndIsActiveTrue(keyPrefix);

            // Verify the plaintext key against the hashes
            for (APIKeyEntity candidate : candidates) {
                // Check if key is not expired
                if (candidate.getExpiresAt() != null && LocalDateTime.now().isAfter(candidate.getExpiresAt())) {
                    continue;
                }

                // Verify the plaintext key against the hashed key
                if (passwordEncoder.matches(plainKey, candidate.getKeyHash())) {
                    // Update last used timestamp
                    candidate.recordUsage();
                    apiKeyRepository.save(candidate);
                    log.debug("API key validated for user: {}", candidate.getUser().getUsername());
                    return candidate.getUser();
                }
            }
        } catch (Exception e) {
            log.debug("Error validating API key", e);
        }

        return null;
    }

    /**
     * Get all API keys for a user
     */
    public List<APIKeyResponse> getAPIKeysForUser(BookLoreUserEntity user) {
        return apiKeyRepository.findByUserOrderByCreatedAtDesc(user)
                .stream()
                .map(this::toResponse)
                .collect(Collectors.toList());
    }

    /**
     * Get active API keys for a user
     */
    public List<APIKeyResponse> getActiveAPIKeysForUser(BookLoreUserEntity user) {
        return apiKeyRepository.findActiveKeysByUser(user)
                .stream()
                .map(this::toResponse)
                .collect(Collectors.toList());
    }

    /**
     * Get a specific API key by ID (verify ownership)
     */
    public APIKeyResponse getAPIKey(Long keyId, BookLoreUserEntity user) {
        APIKeyEntity apiKey = apiKeyRepository.findByIdAndUser(keyId, user)
                .orElseThrow(() -> new APIException("API key not found", HttpStatus.NOT_FOUND));
        return toResponse(apiKey);
    }

    /**
     * Revoke an API key
     */
    @Transactional
    public void revokeAPIKey(Long keyId, BookLoreUserEntity user) {
        APIKeyEntity apiKey = apiKeyRepository.findByIdAndUser(keyId, user)
                .orElseThrow(() -> new APIException("API key not found", HttpStatus.NOT_FOUND));

        apiKey.revoke();
        apiKeyRepository.save(apiKey);
        log.info("Revoked API key: {} for user: {}", keyId, user.getUsername());
    }

    /**
     * Delete an API key
     */
    @Transactional
    public void deleteAPIKey(Long keyId, BookLoreUserEntity user) {
        APIKeyEntity apiKey = apiKeyRepository.findByIdAndUser(keyId, user)
                .orElseThrow(() -> new APIException("API key not found", HttpStatus.NOT_FOUND));

        apiKeyRepository.delete(apiKey);
        log.info("Deleted API key: {} for user: {}", keyId, user.getUsername());
    }

    /**
     * Generate a random plaintext API key
     */
    private String generatePlainKey() {
        SecureRandom random = new SecureRandom();
        byte[] keyBytes = new byte[API_KEY_BYTE_LENGTH];
        random.nextBytes(keyBytes);
        return API_KEY_PREFIX + Base64.getUrlEncoder().withoutPadding().encodeToString(keyBytes);
    }

    /**
     * Convert entity to response DTO
     */
    private APIKeyResponse toResponse(APIKeyEntity entity) {
        return APIKeyResponse.builder()
                .id(entity.getId())
                .name(entity.getName())
                .description(entity.getDescription())
                .isActive(entity.isActive())
                .expiresAt(entity.getExpiresAt())
                .lastUsedAt(entity.getLastUsedAt())
                .createdAt(entity.getCreatedAt())
                .revokedAt(entity.getRevokedAt())
                .valid(entity.isValid())
                .build();
    }
}
