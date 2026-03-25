package io.github.springsecuritystarter.autoconfigure;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

/**
 * Root configuration properties for the security starter.
 * <p>
 * Bound under the {@code spring.security.starter} prefix.
 *
 * <pre>
 * spring.security.starter.public-paths=/api/auth/**,/actuator/health
 * spring.security.starter.cors-enabled=true
 * spring.security.starter.cors-allowed-origins=http://localhost:3000
 * spring.security.starter.audit-enabled=true
 * </pre>
 */
@ConfigurationProperties(prefix = "spring.security.starter")
public class SecurityStarterProperties {

    /**
     * URL patterns to permit without authentication.
     */
    private List<String> publicPaths = new ArrayList<>();

    /**
     * Whether CORS support is enabled. Default: false.
     */
    private boolean corsEnabled = false;

    /**
     * Allowed CORS origins when CORS is enabled.
     */
    private List<String> corsAllowedOrigins = new ArrayList<>();

    /**
     * Whether security audit logging is enabled. Default: true.
     */
    private boolean auditEnabled = true;

    /**
     * OAuth2 integration settings.
     */
    private OAuth2 oauth2 = new OAuth2();

    public static class OAuth2 {
        /**
         * Whether OAuth2 login support is enabled. Default: false.
         */
        private boolean enabled = false;

        /**
         * The default frontend URI to redirect the user to after a successful OAuth2 login.
         * The access and refresh tokens will be appended as URL parameters.
         * Default: "http://localhost:3000/oauth2/redirect"
         */
        private String successRedirectUri = "http://localhost:3000/oauth2/redirect";

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public String getSuccessRedirectUri() {
            return successRedirectUri;
        }

        public void setSuccessRedirectUri(String successRedirectUri) {
            this.successRedirectUri = successRedirectUri;
        }
    }

    // --- Getters and Setters ---

    public List<String> getPublicPaths() {
        return publicPaths;
    }

    public void setPublicPaths(List<String> publicPaths) {
        this.publicPaths = publicPaths;
    }

    public boolean isCorsEnabled() {
        return corsEnabled;
    }

    public void setCorsEnabled(boolean corsEnabled) {
        this.corsEnabled = corsEnabled;
    }

    public List<String> getCorsAllowedOrigins() {
        return corsAllowedOrigins;
    }

    public void setCorsAllowedOrigins(List<String> corsAllowedOrigins) {
        this.corsAllowedOrigins = corsAllowedOrigins;
    }

    public boolean isAuditEnabled() {
        return auditEnabled;
    }

    public void setAuditEnabled(boolean auditEnabled) {
        this.auditEnabled = auditEnabled;
    }

    public OAuth2 getOauth2() {
        return oauth2;
    }

    public void setOauth2(OAuth2 oauth2) {
        this.oauth2 = oauth2;
    }
}
