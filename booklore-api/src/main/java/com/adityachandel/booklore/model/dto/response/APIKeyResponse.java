package com.adityachandel.booklore.model.dto.response;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * Response DTO for API key (without plaintext key)
 */
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class APIKeyResponse {

    @Schema(description = "Unique identifier for the API key")
    private Long id;

    @Schema(description = "Name of the API key")
    private String name;

    @Schema(description = "Description of the API key")
    private String description;

    @Schema(description = "Whether the API key is active")
    private boolean isActive;

    @Schema(description = "Expiration date of the API key")
    private LocalDateTime expiresAt;

    @Schema(description = "Last time this API key was used")
    private LocalDateTime lastUsedAt;

    @Schema(description = "Creation timestamp")
    private LocalDateTime createdAt;

    @Schema(description = "Revocation timestamp (if applicable)")
    private LocalDateTime revokedAt;

    @Schema(description = "Whether the API key is currently valid")
    private boolean valid;
}
