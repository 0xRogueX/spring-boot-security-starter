package io.github.springsecuritystarter.jwt;

import io.github.springsecuritystarter.exception.InvalidTokenException;
import io.github.springsecuritystarter.exception.TokenExpiredException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link JwtTokenProvider}.
 */
class JwtTokenProviderTest {

    private JwtTokenProvider tokenProvider;
    private JwtProperties properties;

    @BeforeEach
    void setUp() {
        properties = new JwtProperties();
        // Generate a valid 256-bit Base64 secret for HMAC-SHA256
        String secret = Base64.getEncoder().encodeToString(
                "this-is-a-test-secret-key-32bytes!".getBytes());
        properties.setSecret(secret);
        properties.setExpiration(3600000L); // 1 hour
        properties.setIssuer("test-issuer");

        tokenProvider = new JwtTokenProvider(properties);
    }

    @Test
    @DisplayName("Should generate a valid JWT token")
    void generateToken_shouldReturnNonNullToken() {
        UserDetails user = createUser("testuser", "ROLE_USER");
        String token = tokenProvider.generateToken(user);

        assertNotNull(token);
        assertFalse(token.isEmpty());
    }

    @Test
    @DisplayName("Should extract username from token")
    void getUsername_shouldReturnCorrectUsername() {
        UserDetails user = createUser("admin", "ROLE_ADMIN");
        String token = tokenProvider.generateToken(user);

        String username = tokenProvider.getUsername(token);
        assertEquals("admin", username);
    }

    @Test
    @DisplayName("Should extract roles from token")
    void getRoles_shouldReturnCorrectRoles() {
        UserDetails user = User.builder()
                .username("user")
                .password("pass")
                .authorities(
                        new SimpleGrantedAuthority("ROLE_USER"),
                        new SimpleGrantedAuthority("ROLE_ADMIN"))
                .build();

        String token = tokenProvider.generateToken(user);
        List<String> roles = tokenProvider.getRoles(token);

        assertNotNull(roles);
        assertTrue(roles.contains("ROLE_USER"));
        assertTrue(roles.contains("ROLE_ADMIN"));
    }

    @Test
    @DisplayName("Should validate a valid token")
    void isTokenValid_withValidToken_shouldReturnTrue() {
        UserDetails user = createUser("testuser", "ROLE_USER");
        String token = tokenProvider.generateToken(user);

        assertTrue(tokenProvider.isTokenValid(token));
    }

    @Test
    @DisplayName("Should reject an invalid token")
    void isTokenValid_withInvalidToken_shouldReturnFalse() {
        assertFalse(tokenProvider.isTokenValid("invalid.token.here"));
    }

    @Test
    @DisplayName("Should reject a tampered token")
    void isTokenValid_withTamperedToken_shouldReturnFalse() {
        UserDetails user = createUser("testuser", "ROLE_USER");
        String token = tokenProvider.generateToken(user);

        // Tamper with the token
        String tampered = token.substring(0, token.length() - 5) + "XXXXX";
        assertFalse(tokenProvider.isTokenValid(tampered));
    }

    @Test
    @DisplayName("Should throw InvalidTokenException for malformed token")
    void validateToken_withMalformedToken_shouldThrowInvalidTokenException() {
        assertThrows(InvalidTokenException.class,
                () -> tokenProvider.validateToken("not-a-jwt"));
    }

    @Test
    @DisplayName("Should throw TokenExpiredException for expired token")
    void validateToken_withExpiredToken_shouldThrowTokenExpiredException() {
        // Create provider with 0ms expiration
        JwtProperties expiredProps = new JwtProperties();
        expiredProps.setSecret(properties.getSecret());
        expiredProps.setExpiration(0L);
        JwtTokenProvider expiredProvider = new JwtTokenProvider(expiredProps);

        UserDetails user = createUser("testuser", "ROLE_USER");
        String token = expiredProvider.generateToken(user);

        assertThrows(TokenExpiredException.class,
                () -> expiredProvider.validateToken(token));
    }

    @Test
    @DisplayName("Should generate different tokens for different users")
    void generateToken_differentUsers_shouldProduceDifferentTokens() {
        String token1 = tokenProvider.generateToken(createUser("user1", "ROLE_USER"));
        String token2 = tokenProvider.generateToken(createUser("user2", "ROLE_ADMIN"));

        assertNotEquals(token1, token2);
    }

    private UserDetails createUser(String username, String... roles) {
        var authorities = java.util.Arrays.stream(roles)
                .map(SimpleGrantedAuthority::new)
                .toList();

        return User.builder()
                .username(username)
                .password("password")
                .authorities(authorities)
                .build();
    }
}
