package com.adityachandel.booklore.config.security.service;

import com.adityachandel.booklore.exception.APIException;
import com.adityachandel.booklore.model.entity.APIKeyEntity;
import com.adityachandel.booklore.model.entity.BookLoreUserEntity;
import com.adityachandel.booklore.model.dto.request.CreateAPIKeyRequest;
import com.adityachandel.booklore.model.dto.response.APIKeyCreatedResponse;
import com.adityachandel.booklore.model.dto.response.APIKeyResponse;
import com.adityachandel.booklore.repository.APIKeyRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDateTime;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class APIKeyServiceTest {

    @Mock
    private APIKeyRepository apiKeyRepository;

    private APIKeyService apiKeyService;
    private PasswordEncoder passwordEncoder;
    private BookLoreUserEntity testUser;

    @BeforeEach
    void setUp() {
        passwordEncoder = new BCryptPasswordEncoder();
        apiKeyService = new APIKeyService(apiKeyRepository, passwordEncoder);

        testUser = BookLoreUserEntity.builder()
                .id(1L)
                .username("testuser")
                .name("Test User")
                .email("test@example.com")
                .build();
    }

    @Test
    void testGenerateAPIKey() {
        CreateAPIKeyRequest request = CreateAPIKeyRequest.builder()
                .name("Test Key")
                .description("Test API Key")
                .build();

        when(apiKeyRepository.existsByUserAndNameIgnoreCase(testUser, "Test Key")).thenReturn(false);
        when(apiKeyRepository.countActiveKeysByUser(testUser)).thenReturn(0L);
        when(apiKeyRepository.save(any(APIKeyEntity.class))).thenAnswer(invocation -> {
            APIKeyEntity entity = invocation.getArgument(0);
            entity.setId(1L);
            return entity;
        });

        APIKeyCreatedResponse response = apiKeyService.generateAPIKey(testUser, request);

        assertNotNull(response);
        assertNotNull(response.getKey());
        assertTrue(response.getKey().startsWith("blk_"));
        assertEquals("Test Key", response.getName());
        assertEquals("Test API Key", response.getDescription());
        assertEquals(1L, response.getId());
    }

    @Test
    void testGenerateAPIKey_DuplicateName() {
        CreateAPIKeyRequest request = CreateAPIKeyRequest.builder()
                .name("Existing Key")
                .build();

        when(apiKeyRepository.existsByUserAndNameIgnoreCase(testUser, "Existing Key")).thenReturn(true);

        APIException exception = assertThrows(APIException.class, () -> apiKeyService.generateAPIKey(testUser, request));
        assertEquals(HttpStatus.CONFLICT, exception.getStatus());
        assertTrue(exception.getMessage().contains("already exists"));
    }

    @Test
    void testGenerateAPIKey_ExceedsMaximumLimit() {
        CreateAPIKeyRequest request = CreateAPIKeyRequest.builder()
                .name("Too Many Keys")
                .build();

        when(apiKeyRepository.existsByUserAndNameIgnoreCase(testUser, "Too Many Keys")).thenReturn(false);
        when(apiKeyRepository.countActiveKeysByUser(testUser)).thenReturn(20L);

        APIException exception = assertThrows(APIException.class, () -> apiKeyService.generateAPIKey(testUser, request));
        assertEquals(HttpStatus.BAD_REQUEST, exception.getStatus());
        assertTrue(exception.getMessage().contains("Maximum number"));
    }

    @Test
    void testValidateAPIKey() {
        String plainKey = "blk_testkey123456789012345678901234567890";
        String keyHash = passwordEncoder.encode(plainKey);
        String keyPrefix = plainKey.substring(0, Math.min(12, plainKey.length()));

        APIKeyEntity validKey = APIKeyEntity.builder()
                .id(1L)
                .user(testUser)
                .keyHash(keyHash)
                .keyPrefix(keyPrefix)
                .name("Test Key")
                .isActive(true)
                .expiresAt(null)
                .revokedAt(null)
                .build();

        when(apiKeyRepository.findByKeyPrefixAndIsActiveTrue(keyPrefix)).thenReturn(List.of(validKey));
        when(apiKeyRepository.save(any(APIKeyEntity.class))).thenReturn(validKey);

        BookLoreUserEntity result = apiKeyService.validateAPIKey(plainKey);

        assertNotNull(result);
        assertEquals(testUser.getUsername(), result.getUsername());
    }

    @Test
    void testValidateAPIKey_Null() {
        assertNull(apiKeyService.validateAPIKey(null));
        assertNull(apiKeyService.validateAPIKey(""));
    }

    @Test
    void testValidateAPIKey_InvalidFormat() {
        assertNull(apiKeyService.validateAPIKey("invalid_key"));
    }

    @Test
    void testValidateAPIKey_Expired() {
        String plainKey = "blk_expiredkey12345678901234567890123456";
        String keyHash = passwordEncoder.encode(plainKey);
        String keyPrefix = plainKey.substring(0, Math.min(12, plainKey.length()));

        APIKeyEntity expiredKey = APIKeyEntity.builder()
                .id(1L)
                .user(testUser)
                .keyHash(keyHash)
                .keyPrefix(keyPrefix)
                .name("Expired Key")
                .isActive(true)
                .expiresAt(LocalDateTime.now().minusDays(1))
                .revokedAt(null)
                .build();

        when(apiKeyRepository.findByKeyPrefixAndIsActiveTrue(keyPrefix)).thenReturn(List.of(expiredKey));

        BookLoreUserEntity result = apiKeyService.validateAPIKey(plainKey);

        assertNull(result);
    }

    @Test
    void testGetAPIKeysForUser() {
        APIKeyEntity key1 = APIKeyEntity.builder()
                .id(1L)
                .user(testUser)
                .name("Key 1")
                .isActive(true)
                .build();

        APIKeyEntity key2 = APIKeyEntity.builder()
                .id(2L)
                .user(testUser)
                .name("Key 2")
                .isActive(false)
                .build();

        when(apiKeyRepository.findByUserOrderByCreatedAtDesc(testUser)).thenReturn(List.of(key1, key2));

        List<APIKeyResponse> responses = apiKeyService.getAPIKeysForUser(testUser);

        assertEquals(2, responses.size());
        assertEquals("Key 1", responses.get(0).getName());
        assertEquals("Key 2", responses.get(1).getName());
    }

    @Test
    void testGetActiveAPIKeysForUser() {
        APIKeyEntity key1 = APIKeyEntity.builder()
                .id(1L)
                .user(testUser)
                .name("Active Key")
                .isActive(true)
                .expiresAt(null)
                .revokedAt(null)
                .build();

        when(apiKeyRepository.findActiveKeysByUser(testUser)).thenReturn(List.of(key1));

        List<APIKeyResponse> responses = apiKeyService.getActiveAPIKeysForUser(testUser);

        assertEquals(1, responses.size());
        assertTrue(responses.get(0).isValid());
    }

    @Test
    void testRevokeAPIKey() {
        APIKeyEntity key = APIKeyEntity.builder()
                .id(1L)
                .user(testUser)
                .name("Key to Revoke")
                .isActive(true)
                .build();

        when(apiKeyRepository.findByIdAndUser(1L, testUser)).thenReturn(Optional.of(key));
        when(apiKeyRepository.save(any(APIKeyEntity.class))).thenReturn(key);

        apiKeyService.revokeAPIKey(1L, testUser);

        assertTrue(key.getRevokedAt() != null);
        assertFalse(key.isActive());
    }

    @Test
    void testDeleteAPIKey() {
        APIKeyEntity key = APIKeyEntity.builder()
                .id(1L)
                .user(testUser)
                .name("Key to Delete")
                .build();

        when(apiKeyRepository.findByIdAndUser(1L, testUser)).thenReturn(Optional.of(key));

        apiKeyService.deleteAPIKey(1L, testUser);

        verify(apiKeyRepository).delete(key);
    }

    @Test
    void testAPIKeyEntity_IsValid() {
        // Valid key
        APIKeyEntity validKey = APIKeyEntity.builder()
                .isActive(true)
                .expiresAt(LocalDateTime.now().plusDays(1))
                .revokedAt(null)
                .build();
        assertTrue(validKey.isValid());

        // Inactive key
        APIKeyEntity inactiveKey = APIKeyEntity.builder()
                .isActive(false)
                .expiresAt(null)
                .revokedAt(LocalDateTime.now())
                .build();
        assertFalse(inactiveKey.isValid());

        // Expired key
        APIKeyEntity expiredKey = APIKeyEntity.builder()
                .isActive(true)
                .expiresAt(LocalDateTime.now().minusDays(1))
                .revokedAt(null)
                .build();
        assertFalse(expiredKey.isValid());
    }
}
