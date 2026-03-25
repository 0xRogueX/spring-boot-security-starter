package io.github.springsecuritystarter.auth;

import io.github.springsecuritystarter.auth.model.RefreshToken;
import io.github.springsecuritystarter.exception.InvalidTokenException;
import io.github.springsecuritystarter.exception.TokenExpiredException;
import io.github.springsecuritystarter.jwt.JwtProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link RefreshTokenService}.
 */
class RefreshTokenServiceTest {

    private RefreshTokenService refreshTokenService;

    @BeforeEach
    void setUp() {
        JwtProperties properties = new JwtProperties();
        properties.setRefreshExpiration(86400000L); // 24 hours
        refreshTokenService = new RefreshTokenService(properties);
    }

    @Test
    @DisplayName("Should create a refresh token")
    void createRefreshToken_shouldReturnNonNullToken() {
        String token = refreshTokenService.createRefreshToken("testuser");
        assertNotNull(token);
        assertFalse(token.isEmpty());
    }

    @Test
    @DisplayName("Should validate and rotate refresh token")
    void validateAndRotate_withValidToken_shouldReturnUsername() {
        String token = refreshTokenService.createRefreshToken("testuser");
        String username = refreshTokenService.validateAndRotate(token);

        assertEquals("testuser", username);
    }

    @Test
    @DisplayName("Rotated token should not be reusable")
    void validateAndRotate_withUsedToken_shouldThrowInvalidTokenException() {
        String token = refreshTokenService.createRefreshToken("testuser");
        refreshTokenService.validateAndRotate(token);

        // Second use should fail
        assertThrows(InvalidTokenException.class,
                () -> refreshTokenService.validateAndRotate(token));
    }

    @Test
    @DisplayName("Should throw for invalid token")
    void validateAndRotate_withInvalidToken_shouldThrowInvalidTokenException() {
        assertThrows(InvalidTokenException.class,
                () -> refreshTokenService.validateAndRotate("nonexistent-token"));
    }

    @Test
    @DisplayName("Should revoke tokens for user")
    void revokeTokensForUser_shouldInvalidateAllTokens() {
        String token = refreshTokenService.createRefreshToken("testuser");
        refreshTokenService.revokeTokensForUser("testuser");

        assertThrows(InvalidTokenException.class,
                () -> refreshTokenService.validateAndRotate(token));
    }

    @Test
    @DisplayName("Should revoke specific token")
    void revokeToken_shouldInvalidateSpecificToken() {
        String token = refreshTokenService.createRefreshToken("testuser");
        refreshTokenService.revokeToken(token);

        assertThrows(InvalidTokenException.class,
                () -> refreshTokenService.validateAndRotate(token));
    }

    @Test
    @DisplayName("Creating new token should revoke previous tokens for same user")
    void createRefreshToken_shouldRevokePreviousTokens() {
        String token1 = refreshTokenService.createRefreshToken("testuser");
        String token2 = refreshTokenService.createRefreshToken("testuser");

        // token1 should be revoked
        assertThrows(InvalidTokenException.class,
                () -> refreshTokenService.validateAndRotate(token1));

        // token2 should still be valid
        String username = refreshTokenService.validateAndRotate(token2);
        assertEquals("testuser", username);
    }

    @Test
    @DisplayName("Should throw TokenExpiredException for expired refresh token")
    void validateAndRotate_withExpiredToken_shouldThrowTokenExpiredException() {
        // Create service with 0ms expiration
        JwtProperties expiredProps = new JwtProperties();
        expiredProps.setRefreshExpiration(0L);
        RefreshTokenService expiredService = new RefreshTokenService(expiredProps);

        String token = expiredService.createRefreshToken("testuser");

        assertThrows(TokenExpiredException.class,
                () -> expiredService.validateAndRotate(token));
    }
}
