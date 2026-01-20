package com.adityachandel.booklore.controller;

import com.adityachandel.booklore.config.security.service.APIKeyService;
import com.adityachandel.booklore.model.dto.request.CreateAPIKeyRequest;
import com.adityachandel.booklore.model.dto.response.APIKeyCreatedResponse;
import com.adityachandel.booklore.model.dto.response.APIKeyResponse;
import com.adityachandel.booklore.model.entity.BookLoreUserEntity;
import com.adityachandel.booklore.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import java.time.LocalDateTime;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class APIKeyControllerTest {

    @Mock
    private APIKeyService apiKeyService;

    @Mock
    private UserRepository userRepository;

    private APIKeyController controller;
    private BookLoreUserEntity testUser;
    private Authentication authentication;

    @BeforeEach
    void setUp() {
        controller = new APIKeyController(apiKeyService, userRepository);

        testUser = BookLoreUserEntity.builder()
                .id(1L)
                .username("testuser")
                .name("Test User")
                .build();

        authentication = new UsernamePasswordAuthenticationToken("testuser", null, Collections.emptyList());
    }

    @Test
    void testCreateAPIKey() {
        CreateAPIKeyRequest request = CreateAPIKeyRequest.builder()
                .name("My API Key")
                .description("For testing")
                .build();

        APIKeyCreatedResponse expectedResponse = APIKeyCreatedResponse.builder()
                .id(1L)
                .key("blk_testkey123456789")
                .name("My API Key")
                .description("For testing")
                .createdAt(LocalDateTime.now())
                .build();

        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(testUser));
        when(apiKeyService.generateAPIKey(testUser, request)).thenReturn(expectedResponse);

        ResponseEntity<APIKeyCreatedResponse> response = controller.createAPIKey(request, authentication);

        assertEquals(HttpStatus.CREATED, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("My API Key", response.getBody().getName());
        assertEquals("blk_testkey123456789", response.getBody().getKey());
    }

    @Test
    void testListAPIKeys() {
        APIKeyResponse key1 = APIKeyResponse.builder()
                .id(1L)
                .name("Key 1")
                .isActive(true)
                .valid(true)
                .build();

        APIKeyResponse key2 = APIKeyResponse.builder()
                .id(2L)
                .name("Key 2")
                .isActive(true)
                .valid(true)
                .build();

        List<APIKeyResponse> keys = List.of(key1, key2);

        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(testUser));
        when(apiKeyService.getAPIKeysForUser(testUser)).thenReturn(keys);

        ResponseEntity<List<APIKeyResponse>> response = controller.listAPIKeys(authentication);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(2, response.getBody().size());
    }

    @Test
    void testListActiveAPIKeys() {
        APIKeyResponse activeKey = APIKeyResponse.builder()
                .id(1L)
                .name("Active Key")
                .isActive(true)
                .valid(true)
                .build();

        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(testUser));
        when(apiKeyService.getActiveAPIKeysForUser(testUser)).thenReturn(List.of(activeKey));

        ResponseEntity<List<APIKeyResponse>> response = controller.listActiveAPIKeys(authentication);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(1, response.getBody().size());
        assertTrue(response.getBody().get(0).isValid());
    }

    @Test
    void testGetAPIKey() {
        APIKeyResponse keyResponse = APIKeyResponse.builder()
                .id(1L)
                .name("My Key")
                .isActive(true)
                .valid(true)
                .build();

        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(testUser));
        when(apiKeyService.getAPIKey(1L, testUser)).thenReturn(keyResponse);

        ResponseEntity<APIKeyResponse> response = controller.getAPIKey(1L, authentication);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("My Key", response.getBody().getName());
    }

    @Test
    void testRevokeAPIKey() {
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(testUser));

        ResponseEntity<Void> response = controller.revokeAPIKey(1L, authentication);

        assertEquals(HttpStatus.NO_CONTENT, response.getStatusCode());
        verify(apiKeyService).revokeAPIKey(1L, testUser);
    }

    @Test
    void testDeleteAPIKey() {
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(testUser));

        ResponseEntity<Void> response = controller.deleteAPIKey(1L, authentication);

        assertEquals(HttpStatus.NO_CONTENT, response.getStatusCode());
        verify(apiKeyService).deleteAPIKey(1L, testUser);
    }
}
