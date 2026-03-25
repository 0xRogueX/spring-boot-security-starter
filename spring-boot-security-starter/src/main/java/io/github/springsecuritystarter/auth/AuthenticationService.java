package io.github.springsecuritystarter.auth;

import io.github.springsecuritystarter.auth.dto.LoginRequest;
import io.github.springsecuritystarter.auth.dto.LoginResponse;
import io.github.springsecuritystarter.auth.dto.RefreshTokenRequest;
import io.github.springsecuritystarter.auth.dto.RefreshTokenResponse;
import io.github.springsecuritystarter.jwt.JwtProperties;
import io.github.springsecuritystarter.jwt.JwtTokenProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

import java.util.List;
import java.util.stream.Collectors;

/**
 * Service encapsulating authentication logic: login and token refresh.
 * <p>
 * This service is meant to be used by controllers in consuming applications,
 * or by the auto-configured {@code AuthController} if enabled.
 *
 * <h3>Usage</h3>
 * <pre>
 * &#64;Autowired
 * private AuthenticationService authService;
 *
 * LoginResponse response = authService.authenticate(loginRequest);
 * RefreshTokenResponse refreshed = authService.refresh(refreshRequest);
 * </pre>
 */
public class AuthenticationService {

    private static final Logger log = LoggerFactory.getLogger(AuthenticationService.class);

    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider tokenProvider;
    private final RefreshTokenService refreshTokenService;
    private final UserDetailsService userDetailsService;
    private final JwtProperties jwtProperties;

    public AuthenticationService(AuthenticationManager authenticationManager,
                                  JwtTokenProvider tokenProvider,
                                  RefreshTokenService refreshTokenService,
                                  UserDetailsService userDetailsService,
                                  JwtProperties jwtProperties) {
        this.authenticationManager = authenticationManager;
        this.tokenProvider = tokenProvider;
        this.refreshTokenService = refreshTokenService;
        this.userDetailsService = userDetailsService;
        this.jwtProperties = jwtProperties;
    }

    /**
     * Authenticate a user and return JWT access + refresh tokens.
     *
     * @param request the login credentials
     * @return response containing tokens and user info
     */
    public LoginResponse authenticate(LoginRequest request) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));

        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        String accessToken = tokenProvider.generateToken(userDetails);
        String refreshToken = refreshTokenService.createRefreshToken(userDetails.getUsername());

        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        log.info("User '{}' authenticated successfully", userDetails.getUsername());

        return new LoginResponse(accessToken, refreshToken, jwtProperties.getExpiration(),
                userDetails.getUsername(), roles);
    }

    /**
     * Refresh an access token using a valid refresh token.
     * Implements token rotation: the old refresh token is invalidated.
     *
     * @param request the refresh token
     * @return new access and refresh tokens
     */
    public RefreshTokenResponse refresh(RefreshTokenRequest request) {
        String username = refreshTokenService.validateAndRotate(request.getRefreshToken());

        UserDetails userDetails = userDetailsService.loadUserByUsername(username);
        String newAccessToken = tokenProvider.generateToken(userDetails);
        String newRefreshToken = refreshTokenService.createRefreshToken(username);

        log.info("Token refreshed for user '{}'", username);

        return new RefreshTokenResponse(newAccessToken, newRefreshToken);
    }

    /**
     * Revoke all tokens for a user (logout).
     *
     * @param username the user to revoke tokens for
     */
    public void logout(String username) {
        refreshTokenService.revokeTokensForUser(username);
        log.info("User '{}' logged out — refresh tokens revoked", username);
    }
}
