package com.adityachandel.booklore.controller;

import com.adityachandel.booklore.config.security.service.APIKeyService;
import com.adityachandel.booklore.model.dto.request.CreateAPIKeyRequest;
import com.adityachandel.booklore.model.dto.response.APIKeyCreatedResponse;
import com.adityachandel.booklore.model.dto.response.APIKeyResponse;
import com.adityachandel.booklore.model.entity.BookLoreUserEntity;
import com.adityachandel.booklore.repository.UserRepository;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * REST Controller for managing API Keys
 * Endpoints for creating, listing, and revoking API keys for programmatic access
 */
@Tag(name = "API Keys", description = "Endpoints for managing API keys for programmatic access")
@Slf4j
@AllArgsConstructor
@RestController
@RequestMapping("/api/v1/api-keys")
public class APIKeyController {

    private final APIKeyService apiKeyService;
    private final UserRepository userRepository;

    /**
     * Generate a new API key for the authenticated user
     */
    @Operation(
            summary = "Generate a new API key",
            description = "Create a new API key for programmatic access to the BookLore API. The plaintext key is returned only once."
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "201",
                    description = "API key created successfully",
                    content = @Content(schema = @Schema(implementation = APIKeyCreatedResponse.class))
            ),
            @ApiResponse(responseCode = "400", description = "Invalid request or key limit reached"),
            @ApiResponse(responseCode = "401", description = "User not authenticated"),
            @ApiResponse(responseCode = "409", description = "API key with this name already exists")
    })
    @PostMapping
    public ResponseEntity<APIKeyCreatedResponse> createAPIKey(
            @Parameter(description = "API key creation request") @Valid @RequestBody CreateAPIKeyRequest request,
            Authentication authentication) {
        
        String username = authentication.getName();
        BookLoreUserEntity user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalStateException("User not found: " + username));

        APIKeyCreatedResponse response = apiKeyService.generateAPIKey(user, request);
        
        log.info("API key created for user: {}", username);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    /**
     * List all API keys for the authenticated user
     */
    @Operation(
            summary = "List all API keys",
            description = "Retrieve all API keys (active and inactive) for the authenticated user"
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "List of API keys",
                    content = @Content(schema = @Schema(implementation = APIKeyResponse.class))
            ),
            @ApiResponse(responseCode = "401", description = "User not authenticated")
    })
    @GetMapping
    public ResponseEntity<List<APIKeyResponse>> listAPIKeys(Authentication authentication) {
        String username = authentication.getName();
        BookLoreUserEntity user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalStateException("User not found: " + username));

        List<APIKeyResponse> keys = apiKeyService.getAPIKeysForUser(user);
        return ResponseEntity.ok(keys);
    }

    /**
     * List only active API keys for the authenticated user
     */
    @Operation(
            summary = "List active API keys",
            description = "Retrieve only active API keys for the authenticated user"
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "List of active API keys",
                    content = @Content(schema = @Schema(implementation = APIKeyResponse.class))
            ),
            @ApiResponse(responseCode = "401", description = "User not authenticated")
    })
    @GetMapping("/active")
    public ResponseEntity<List<APIKeyResponse>> listActiveAPIKeys(Authentication authentication) {
        String username = authentication.getName();
        BookLoreUserEntity user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalStateException("User not found: " + username));

        List<APIKeyResponse> keys = apiKeyService.getActiveAPIKeysForUser(user);
        return ResponseEntity.ok(keys);
    }

    /**
     * Get details of a specific API key
     */
    @Operation(
            summary = "Get API key details",
            description = "Retrieve details of a specific API key by ID"
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "API key details",
                    content = @Content(schema = @Schema(implementation = APIKeyResponse.class))
            ),
            @ApiResponse(responseCode = "401", description = "User not authenticated"),
            @ApiResponse(responseCode = "404", description = "API key not found")
    })
    @GetMapping("/{keyId}")
    public ResponseEntity<APIKeyResponse> getAPIKey(
            @Parameter(description = "The API key ID") @PathVariable Long keyId,
            Authentication authentication) {
        
        String username = authentication.getName();
        BookLoreUserEntity user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalStateException("User not found: " + username));

        APIKeyResponse key = apiKeyService.getAPIKey(keyId, user);
        return ResponseEntity.ok(key);
    }

    /**
     * Revoke an API key (soft delete)
     */
    @Operation(
            summary = "Revoke an API key",
            description = "Revoke an API key, preventing further use"
    )
    @ApiResponses({
            @ApiResponse(responseCode = "204", description = "API key revoked successfully"),
            @ApiResponse(responseCode = "401", description = "User not authenticated"),
            @ApiResponse(responseCode = "404", description = "API key not found")
    })
    @PostMapping("/{keyId}/revoke")
    public ResponseEntity<Void> revokeAPIKey(
            @Parameter(description = "The API key ID") @PathVariable Long keyId,
            Authentication authentication) {
        
        String username = authentication.getName();
        BookLoreUserEntity user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalStateException("User not found: " + username));

        apiKeyService.revokeAPIKey(keyId, user);
        
        log.info("API key revoked for user: {}", username);
        return ResponseEntity.noContent().build();
    }

    /**
     * Delete an API key permanently
     */
    @Operation(
            summary = "Delete an API key",
            description = "Permanently delete an API key"
    )
    @ApiResponses({
            @ApiResponse(responseCode = "204", description = "API key deleted successfully"),
            @ApiResponse(responseCode = "401", description = "User not authenticated"),
            @ApiResponse(responseCode = "404", description = "API key not found")
    })
    @DeleteMapping("/{keyId}")
    public ResponseEntity<Void> deleteAPIKey(
            @Parameter(description = "The API key ID") @PathVariable Long keyId,
            Authentication authentication) {
        
        String username = authentication.getName();
        BookLoreUserEntity user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalStateException("User not found: " + username));

        apiKeyService.deleteAPIKey(keyId, user);
        
        log.info("API key deleted for user: {}", username);
        return ResponseEntity.noContent().build();
    }
}
