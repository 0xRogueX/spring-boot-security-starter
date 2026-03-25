package io.github.springsecuritystarter.auth;

import io.github.springsecuritystarter.auth.model.RefreshToken;
import io.github.springsecuritystarter.exception.InvalidTokenException;
import io.github.springsecuritystarter.exception.TokenExpiredException;
import io.github.springsecuritystarter.jwt.JwtProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory refresh token store.
 * <p>
 * Manages creation, validation, rotation, and revocation of opaque refresh tokens.
 * Tokens are stored in a {@link ConcurrentHashMap} and are thread-safe.
 *
 * <h3>Production Note</h3>
 * For production deployments, consider replacing this with a persistent store
 * (e.g., Redis or database-backed implementation) by creating a custom bean
 * that overrides this one.
 */
public class RefreshTokenService {

    private static final Logger log = LoggerFactory.getLogger(RefreshTokenService.class);

    private final Map<String, RefreshToken> tokenStore = new ConcurrentHashMap<>();
    private final JwtProperties jwtProperties;

    public RefreshTokenService(JwtProperties jwtProperties) {
        this.jwtProperties = jwtProperties;
    }

    /**
     * Create a new refresh token for the given username.
     *
     * @param username the authenticated user's username
     * @return the refresh token string
     */
    public String createRefreshToken(String username) {
        // Revoke any existing refresh tokens for this user
        revokeTokensForUser(username);

        String tokenValue = UUID.randomUUID().toString();
        Instant expiryDate = Instant.now().plusMillis(jwtProperties.getRefreshExpiration());

        RefreshToken refreshToken = new RefreshToken(tokenValue, username, expiryDate);
        tokenStore.put(tokenValue, refreshToken);

        log.debug("Created refresh token for user '{}'", username);
        return tokenValue;
    }

    /**
     * Validate and consume a refresh token (token rotation).
     * The old token is revoked and a new one is issued.
     *
     * @param token the refresh token string
     * @return the username associated with the token
     * @throws InvalidTokenException  if the token does not exist
     * @throws TokenExpiredException if the token has expired
     */
    public String validateAndRotate(String token) {
        RefreshToken refreshToken = Optional.ofNullable(tokenStore.remove(token))
                .orElseThrow(() -> new InvalidTokenException("Invalid refresh token"));

        if (refreshToken.isExpired()) {
            log.warn("Expired refresh token used for user '{}'", refreshToken.getUsername());
            throw new TokenExpiredException("Refresh token has expired");
        }

        log.debug("Validated refresh token for user '{}'", refreshToken.getUsername());
        return refreshToken.getUsername();
    }

    /**
     * Revoke all refresh tokens for a given user.
     *
     * @param username the username whose tokens to revoke
     */
    public void revokeTokensForUser(String username) {
        tokenStore.entrySet().removeIf(entry -> entry.getValue().getUsername().equals(username));
    }

    /**
     * Revoke a specific refresh token.
     *
     * @param token the token to revoke
     */
    public void revokeToken(String token) {
        tokenStore.remove(token);
    }
}
