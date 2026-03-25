package io.github.springsecuritystarter.audit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;

/**
 * Audit logger that listens to Spring Security authentication events.
 * <p>
 * Logs successful and failed authentication attempts for security auditing.
 * Enabled/disabled via {@code spring.security.starter.audit.enabled} property.
 *
 * <h3>Logged Events</h3>
 * <ul>
 *   <li>Authentication success — username, authorities</li>
 *   <li>Authentication failure — username, exception type</li>
 * </ul>
 *
 * <h3>Customization</h3>
 * To add custom audit behavior (e.g., database persistence), create your own
 * bean that overrides this one:
 * <pre>
 * &#64;Bean
 * public SecurityAuditLogger customAuditLogger() {
 *     return new MyCustomAuditLogger();
 * }
 * </pre>
 */
public class SecurityAuditLogger {

    private static final Logger audit = LoggerFactory.getLogger("SECURITY_AUDIT");

    @EventListener
    public void onAuthenticationSuccess(AuthenticationSuccessEvent event) {
        Authentication auth = event.getAuthentication();
        audit.info("LOGIN_SUCCESS | user={} | authorities={}",
                auth.getName(), auth.getAuthorities());
    }

    @EventListener
    public void onAuthenticationFailure(AbstractAuthenticationFailureEvent event) {
        audit.warn("LOGIN_FAILURE | user={} | exception={}",
                event.getAuthentication().getName(),
                event.getException().getClass().getSimpleName());
    }
}
