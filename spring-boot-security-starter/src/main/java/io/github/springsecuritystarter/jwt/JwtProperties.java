package io.github.springsecuritystarter.jwt;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration properties for JWT token handling.
 * <p>
 * All properties are bound under the {@code spring.security.starter.jwt} prefix.
 *
 * <pre>
 * spring.security.starter.jwt.secret=YOUR_BASE64_ENCODED_SECRET_KEY
 * spring.security.starter.jwt.expiration=3600000
 * spring.security.starter.jwt.refresh-expiration=86400000
 * spring.security.starter.jwt.header=Authorization
 * spring.security.starter.jwt.prefix=Bearer 
 * spring.security.starter.jwt.issuer=spring-security-starter
 * </pre>
 */
@ConfigurationProperties(prefix = "spring.security.starter.jwt")
public class JwtProperties {

    /**
     * Base64-encoded secret key for HMAC-SHA signing.
     * <strong>Required.</strong> The starter will not activate without this.
     */
    private String secret;

    /**
     * Access token expiration time in milliseconds. Default: 3600000 (1 hour).
     */
    private long expiration = 3_600_000L;

    /**
     * Refresh token expiration time in milliseconds. Default: 86400000 (24 hours).
     */
    private long refreshExpiration = 86_400_000L;

    /**
     * HTTP header name for the JWT token. Default: "Authorization".
     */
    private String header = "Authorization";

    /**
     * Token prefix in the header value. Default: "Bearer ".
     */
    private String prefix = "Bearer ";

    /**
     * Optional issuer claim to include in generated tokens.
     */
    private String issuer = "spring-security-starter";

    // --- Getters and Setters ---

    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

    public long getExpiration() {
        return expiration;
    }

    public void setExpiration(long expiration) {
        this.expiration = expiration;
    }

    public long getRefreshExpiration() {
        return refreshExpiration;
    }

    public void setRefreshExpiration(long refreshExpiration) {
        this.refreshExpiration = refreshExpiration;
    }

    public String getHeader() {
        return header;
    }

    public void setHeader(String header) {
        this.header = header;
    }

    public String getPrefix() {
        return prefix;
    }

    public void setPrefix(String prefix) {
        this.prefix = prefix;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }
}
