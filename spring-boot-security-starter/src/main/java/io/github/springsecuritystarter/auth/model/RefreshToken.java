package io.github.springsecuritystarter.auth.model;

import java.time.Instant;

/**
 * Represents a refresh token stored in memory.
 * <p>
 * Refresh tokens are opaque strings mapped to a username with an expiry timestamp.
 * They are used to obtain new access tokens without re-authenticating.
 */
public class RefreshToken {

    private String token;
    private String username;
    private Instant expiryDate;

    public RefreshToken() {
    }

    public RefreshToken(String token, String username, Instant expiryDate) {
        this.token = token;
        this.username = username;
        this.expiryDate = expiryDate;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public Instant getExpiryDate() {
        return expiryDate;
    }

    public void setExpiryDate(Instant expiryDate) {
        this.expiryDate = expiryDate;
    }

    public boolean isExpired() {
        return Instant.now().isAfter(expiryDate);
    }
}
