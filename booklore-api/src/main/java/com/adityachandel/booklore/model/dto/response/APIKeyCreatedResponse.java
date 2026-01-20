package com.adityachandel.booklore.model.dto.response;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * Response DTO for API key that includes the plaintext key (only shown once after creation)
 */
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class APIKeyCreatedResponse {

    @Schema(description = "Unique identifier for the API key")
    private Long id;

    @Schema(description = "The plaintext API key (only displayed once after creation)", example = "blk_1a2b3c4d5e6f7g8h9i0j")
    private String key;

    @Schema(description = "Name of the API key")
    private String name;

    @Schema(description = "Description of the API key")
    private String description;

    @Schema(description = "Expiration date of the API key")
    private LocalDateTime expiresAt;

    @Schema(description = "Creation timestamp")
    private LocalDateTime createdAt;

    @Schema(description = "Instruction for storing the key securely")
    @Builder.Default
    private String warning = "Store this key securely. You won't be able to see it again. Anyone with this key can access the API on your behalf.";
}
