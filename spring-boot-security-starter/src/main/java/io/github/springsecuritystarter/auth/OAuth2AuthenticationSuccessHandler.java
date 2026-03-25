package io.github.springsecuritystarter.auth;

import io.github.springsecuritystarter.autoconfigure.SecurityStarterProperties;
import io.github.springsecuritystarter.jwt.JwtTokenProvider;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.util.Collection;
import java.util.stream.Collectors;

/**
 * Handles successful OAuth2 logins by issuing a native JWT token and redirecting
 * the user back to the configured SPA/frontend with the tokens in the URL.
 */
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private static final Logger log = LoggerFactory.getLogger(OAuth2AuthenticationSuccessHandler.class);

    private final JwtTokenProvider tokenProvider;
    private final RefreshTokenService refreshTokenService;
    private final SecurityStarterProperties properties;

    public OAuth2AuthenticationSuccessHandler(JwtTokenProvider tokenProvider,
                                              RefreshTokenService refreshTokenService,
                                              SecurityStarterProperties properties) {
        this.tokenProvider = tokenProvider;
        this.refreshTokenService = refreshTokenService;
        this.properties = properties;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {

        String targetUrl = determineTargetUrl(request, response, authentication);

        if (response.isCommitted()) {
            log.debug("Response has already been committed. Unable to redirect to {}", targetUrl);
            return;
        }

        log.info("OAuth2 login successful for user, generating JWT and redirecting");
        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }

    @Override
    protected String determineTargetUrl(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) {

        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        
        // Use email as username if available, fallback to the subjective ID or name
        String username = extractUsername(oAuth2User);

        // Map OAuth2 authority to standard roles if needed. Default maps everything to ROLE_USER.
        Collection<GrantedAuthority> authorities = oAuth2User.getAuthorities().stream()
                .map(auth -> new SimpleGrantedAuthority("ROLE_USER"))
                .collect(Collectors.toSet());

        User userDetails = new User(username, "", authorities);

        String accessToken = tokenProvider.generateToken(userDetails);
        String refreshToken = refreshTokenService.createRefreshToken(username);

        String redirectUri = properties.getOauth2().getSuccessRedirectUri();

        return UriComponentsBuilder.fromUriString(redirectUri)
                .queryParam("accessToken", accessToken)
                .queryParam("refreshToken", refreshToken)
                .build().toUriString();
    }

    private String extractUsername(OAuth2User oAuth2User) {
        if (oAuth2User.getAttributes().containsKey("email")) {
            return oAuth2User.getAttribute("email");
        }
        if (oAuth2User.getAttributes().containsKey("login")) { // GitHub
            return oAuth2User.getAttribute("login");
        }
        return oAuth2User.getName();
    }
}
