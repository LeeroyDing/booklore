package com.adityachandel.booklore.model.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * Request DTO for creating a new API key
 */
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class CreateAPIKeyRequest {

    @NotBlank(message = "API key name is required")
    @Size(min = 1, max = 100, message = "API key name must be between 1 and 100 characters")
    @Schema(description = "Name for the API key", example = "My Integration")
    private String name;

    @Size(max = 500, message = "Description must not exceed 500 characters")
    @Schema(description = "Optional description for the API key", example = "Used for mobile app integration")
    private String description;

    @Schema(description = "Optional expiration date for the API key (ISO-8601 format)", example = "2026-12-31T23:59:59")
    private LocalDateTime expiresAt;
}
