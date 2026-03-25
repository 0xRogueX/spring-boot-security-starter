package io.github.springsecuritystarter.autoconfigure;

import io.github.springsecuritystarter.audit.SecurityAuditLogger;
import io.github.springsecuritystarter.auth.AuthenticationService;
import io.github.springsecuritystarter.auth.RefreshTokenService;
import io.github.springsecuritystarter.exception.SecurityExceptionHandler;
import io.github.springsecuritystarter.jwt.JwtAuthenticationEntryPoint;
import io.github.springsecuritystarter.jwt.JwtAuthenticationFilter;
import io.github.springsecuritystarter.jwt.JwtTokenProvider;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests that the auto-configuration correctly registers beans
 * when properties are set and skips them when not.
 */
class SecurityStarterAutoConfigurationTest {

    private static final String TEST_SECRET = Base64.getEncoder().encodeToString(
            "this-is-a-test-secret-key-32bytes!".getBytes());

    private final WebApplicationContextRunner contextRunner = new WebApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(
                    SecurityAutoConfiguration.class,
                    SecurityStarterAutoConfiguration.class))
            .withBean(UserDetailsService.class, () -> {
                PasswordEncoder encoder = new org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder();
                return new InMemoryUserDetailsManager(
                        User.builder()
                                .username("test")
                                .password(encoder.encode("test"))
                                .roles("USER")
                                .build());
            });

    @Test
    @DisplayName("Should register all beans when jwt.secret is configured")
    void whenSecretConfigured_shouldRegisterAllBeans() {
        contextRunner
                .withPropertyValues("spring.security.starter.jwt.secret=" + TEST_SECRET)
                .run(context -> {
                    assertThat(context).hasSingleBean(JwtTokenProvider.class);
                    assertThat(context).hasSingleBean(JwtAuthenticationFilter.class);
                    assertThat(context).hasSingleBean(JwtAuthenticationEntryPoint.class);
                    assertThat(context).hasSingleBean(RefreshTokenService.class);
                    assertThat(context).hasSingleBean(SecurityExceptionHandler.class);
                    assertThat(context).hasSingleBean(SecurityFilterChain.class);
                    assertThat(context).hasSingleBean(SecurityAuditLogger.class);
                });
    }

    @Test
    @DisplayName("Should not register beans when jwt.secret is not configured")
    void whenSecretNotConfigured_shouldNotRegisterBeans() {
        contextRunner
                .run(context -> {
                    assertThat(context).doesNotHaveBean(JwtTokenProvider.class);
                    assertThat(context).doesNotHaveBean(JwtAuthenticationFilter.class);
                });
    }

    @Test
    @DisplayName("Should disable audit logger when audit-enabled is false")
    void whenAuditDisabled_shouldNotRegisterAuditLogger() {
        contextRunner
                .withPropertyValues(
                        "spring.security.starter.jwt.secret=" + TEST_SECRET,
                        "spring.security.starter.audit-enabled=false")
                .run(context -> {
                    assertThat(context).doesNotHaveBean(SecurityAuditLogger.class);
                });
    }
}
