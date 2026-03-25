package io.github.springsecuritystarter.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import io.github.springsecuritystarter.exception.InvalidTokenException;
import io.github.springsecuritystarter.exception.TokenExpiredException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import javax.crypto.SecretKey;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Provides JWT token generation, parsing, and validation.
 * <p>
 * This class is configured via {@link JwtProperties} and registered as a Spring bean
 * through auto-configuration. It is stateless and thread-safe.
 *
 * <h3>Usage</h3>
 * <pre>
 * &#64;Autowired
 * private JwtTokenProvider tokenProvider;
 *
 * String token = tokenProvider.generateToken(userDetails);
 * String username = tokenProvider.getUsername(token);
 * </pre>
 */
public class JwtTokenProvider {

    private static final Logger log = LoggerFactory.getLogger(JwtTokenProvider.class);

    private final JwtProperties properties;
    private final SecretKey signingKey;

    public JwtTokenProvider(JwtProperties properties) {
        this.properties = properties;
        this.signingKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(properties.getSecret()));
    }

    /**
     * Generate a JWT access token for the given user.
     *
     * @param userDetails the authenticated user
     * @return signed JWT string
     */
    public String generateToken(UserDetails userDetails) {
        return generateToken(userDetails.getUsername(), userDetails.getAuthorities());
    }

    /**
     * Generate a JWT access token for the given username and authorities.
     *
     * @param username    the subject
     * @param authorities the granted authorities to embed as claims
     * @return signed JWT string
     */
    public String generateToken(String username, Collection<? extends GrantedAuthority> authorities) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + properties.getExpiration());

        List<String> roles = authorities.stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        JwtBuilder builder = Jwts.builder()
                .subject(username)
                .claim("roles", roles)
                .issuedAt(now)
                .expiration(expiry)
                .signWith(signingKey);

        if (properties.getIssuer() != null && !properties.getIssuer().isBlank()) {
            builder.issuer(properties.getIssuer());
        }

        return builder.compact();
    }

    /**
     * Extract the username (subject) from a JWT token.
     *
     * @param token the JWT string
     * @return the username
     * @throws InvalidTokenException if the token is malformed or invalid
     */
    public String getUsername(String token) {
        return parseClaims(token).getSubject();
    }

    /**
     * Extract the roles from a JWT token.
     *
     * @param token the JWT string
     * @return list of role strings
     */
    @SuppressWarnings("unchecked")
    public List<String> getRoles(String token) {
        return parseClaims(token).get("roles", List.class);
    }

    /**
     * Validate a JWT token. Returns {@code true} if valid, {@code false} otherwise.
     * Throws typed exceptions for expired and invalid tokens.
     *
     * @param token the JWT string
     * @return true if the token is valid
     * @throws TokenExpiredException if the token has expired
     * @throws InvalidTokenException if the token is malformed or has an invalid signature
     */
    public boolean validateToken(String token) {
        try {
            parseClaims(token);
            return true;
        } catch (TokenExpiredException e) {
            throw e;
        } catch (InvalidTokenException e) {
            throw e;
        }
    }

    /**
     * Check whether a token is valid without throwing exceptions.
     *
     * @param token the JWT string
     * @return true if the token is valid and not expired
     */
    public boolean isTokenValid(String token) {
        try {
            parseClaims(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private Claims parseClaims(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(signingKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (ExpiredJwtException e) {
            log.warn("JWT token expired for subject: {}", e.getClaims().getSubject());
            throw new TokenExpiredException("JWT token has expired", e);
        } catch (MalformedJwtException e) {
            log.warn("Malformed JWT token: {}", e.getMessage());
            throw new InvalidTokenException("Malformed JWT token", e);
        } catch (SignatureException e) {
            log.warn("Invalid JWT signature: {}", e.getMessage());
            throw new InvalidTokenException("Invalid JWT signature", e);
        } catch (UnsupportedJwtException e) {
            log.warn("Unsupported JWT token: {}", e.getMessage());
            throw new InvalidTokenException("Unsupported JWT token", e);
        } catch (IllegalArgumentException e) {
            log.warn("JWT claims string is empty: {}", e.getMessage());
            throw new InvalidTokenException("JWT claims string is empty", e);
        }
    }
}
