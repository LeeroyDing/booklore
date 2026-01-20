package com.adityachandel.booklore.config.security.filter;

import com.adityachandel.booklore.config.security.service.APIKeyService;
import com.adityachandel.booklore.model.entity.BookLoreUserEntity;
import com.adityachandel.booklore.repository.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Authentication filter for API Key validation
 * Checks for API key in the X-API-Key header or Bearer token scheme
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class APIKeyAuthenticationFilter extends OncePerRequestFilter {

    private final APIKeyService apiKeyService;
    private final UserRepository userRepository;

    private static final String API_KEY_HEADER = "X-API-Key";
    private static final String BEARER_SCHEME = "Bearer ";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        try {
            String apiKey = extractAPIKey(request);
            
            if (apiKey != null) {
                BookLoreUserEntity user = apiKeyService.validateAPIKey(apiKey);
                
                if (user != null) {
                    // Create authentication token (no authorities needed for API key auth, permission checks happen elsewhere)
                    Authentication authentication = new UsernamePasswordAuthenticationToken(
                            user,
                            null,
                            null
                    );
                    
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                    log.debug("API Key authentication successful for user: {}", user.getUsername());
                }
            }
        } catch (Exception e) {
            log.debug("Error during API Key authentication", e);
        }

        filterChain.doFilter(request, response);
    }

    /**
     * Extract API key from request headers
     * Supports both X-API-Key header and Bearer scheme in Authorization header
     */
    private String extractAPIKey(HttpServletRequest request) {
        // Try X-API-Key header first (standard custom header)
        String apiKey = request.getHeader(API_KEY_HEADER);
        if (apiKey != null && !apiKey.isEmpty()) {
            return apiKey;
        }

        // Try Authorization header with Bearer scheme
        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authHeader != null && authHeader.startsWith(BEARER_SCHEME)) {
            String token = authHeader.substring(BEARER_SCHEME.length());
            // Verify it looks like an API key (starts with blk_)
            if (token.startsWith("blk_")) {
                return token;
            }
        }

        return null;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        // Don't filter certain paths that don't require API key authentication
        String path = request.getRequestURI();
        
        // Public endpoints that don't need API key
        return path.contains("/api/v1/auth") || 
               path.contains("/api/v1/public-settings") ||
               path.contains("/api/v1/setup") ||
               path.contains("/api/v1/healthcheck") ||
               path.contains("/api-docs") ||
               path.contains("/swagger-ui");
    }
}
