package io.github.springsecuritystarter.autoconfigure;

import io.github.springsecuritystarter.audit.SecurityAuditLogger;
import io.github.springsecuritystarter.auth.AuthenticationService;
import io.github.springsecuritystarter.auth.RefreshTokenService;
import io.github.springsecuritystarter.exception.SecurityExceptionHandler;
import io.github.springsecuritystarter.jwt.JwtAuthenticationEntryPoint;
import io.github.springsecuritystarter.jwt.JwtAuthenticationFilter;
import io.github.springsecuritystarter.jwt.JwtProperties;
import io.github.springsecuritystarter.jwt.JwtTokenProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import io.github.springsecuritystarter.auth.OAuth2AuthenticationSuccessHandler;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

/**
 * Spring Boot auto-configuration for the security starter.
 * <p>
 * Activates when {@code spring.security.starter.jwt.secret} is set.
 * Registers JWT infrastructure, authentication services, security filter chain,
 * exception handling, and optional audit logging.
 *
 * <h3>Conditionals</h3>
 * <ul>
 *   <li>All JWT beans require {@code spring.security.starter.jwt.secret}</li>
 *   <li>Audit logging requires {@code spring.security.starter.audit-enabled=true} (default)</li>
 *   <li>All beans use {@code @ConditionalOnMissingBean} so consumers can override</li>
 * </ul>
 */
@AutoConfiguration
@EnableWebSecurity
@EnableMethodSecurity
@EnableConfigurationProperties({JwtProperties.class, SecurityStarterProperties.class})
@ConditionalOnProperty(prefix = "spring.security.starter.jwt", name = "secret")
public class SecurityStarterAutoConfiguration {

    // ========== JWT Beans ==========

    @Bean
    @ConditionalOnMissingBean
    public JwtTokenProvider jwtTokenProvider(JwtProperties jwtProperties) {
        return new JwtTokenProvider(jwtProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    public JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint() {
        return new JwtAuthenticationEntryPoint();
    }

    @Bean
    @ConditionalOnMissingBean
    public JwtAuthenticationFilter jwtAuthenticationFilter(JwtTokenProvider tokenProvider,
                                                            UserDetailsService userDetailsService,
                                                            JwtProperties jwtProperties) {
        return new JwtAuthenticationFilter(tokenProvider, userDetailsService, jwtProperties);
    }

    // ========== Auth Beans ==========

    @Bean
    @ConditionalOnMissingBean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    @ConditionalOnMissingBean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    @ConditionalOnMissingBean
    public RefreshTokenService refreshTokenService(JwtProperties jwtProperties) {
        return new RefreshTokenService(jwtProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    public AuthenticationService authenticationService(AuthenticationManager authenticationManager,
                                                        JwtTokenProvider tokenProvider,
                                                        RefreshTokenService refreshTokenService,
                                                        UserDetailsService userDetailsService,
                                                        JwtProperties jwtProperties) {
        return new AuthenticationService(authenticationManager, tokenProvider,
                refreshTokenService, userDetailsService, jwtProperties);
    }

    // ========== Exception Handling ==========

    @Bean
    @ConditionalOnMissingBean
    public SecurityExceptionHandler securityExceptionHandler() {
        return new SecurityExceptionHandler();
    }

    // ========== Audit ==========

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "spring.security.starter", name = "audit-enabled", havingValue = "true", matchIfMissing = true)
    public SecurityAuditLogger securityAuditLogger() {
        return new SecurityAuditLogger();
    }

    // ========== OAuth2 ==========

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "spring.security.starter.oauth2", name = "enabled", havingValue = "true")
    public OAuth2AuthenticationSuccessHandler oauth2AuthenticationSuccessHandler(
            JwtTokenProvider tokenProvider,
            RefreshTokenService refreshTokenService,
            SecurityStarterProperties properties) {
        return new OAuth2AuthenticationSuccessHandler(tokenProvider, refreshTokenService, properties);
    }

    // ========== Security Filter Chain ==========

    @Bean
    @ConditionalOnMissingBean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                    JwtAuthenticationFilter jwtFilter,
                                                    JwtAuthenticationEntryPoint entryPoint,
                                                    SecurityStarterProperties properties,
                                                    ObjectProvider<OAuth2AuthenticationSuccessHandler> oauth2SuccessHandler) throws Exception {
        http
                // Stateless session — no JSESSIONID cookies
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // Disable CSRF for stateless APIs (tokens provide CSRF protection)
                .csrf(AbstractHttpConfigurer::disable)

                // Configure authorization
                .authorizeHttpRequests(auth -> {
                    // Permit configured public paths
                    if (!properties.getPublicPaths().isEmpty()) {
                        auth.requestMatchers(properties.getPublicPaths().toArray(String[]::new)).permitAll();
                    }
                    auth.anyRequest().authenticated();
                })

                // JWT entry point for 401 errors
                .exceptionHandling(exception ->
                        exception.authenticationEntryPoint(entryPoint))

                // Add JWT filter before the username/password filter
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);

        // OAuth2 integration
        if (properties.getOauth2().isEnabled()) {
            OAuth2AuthenticationSuccessHandler handler = oauth2SuccessHandler.getIfAvailable();
            if (handler != null) {
                http.oauth2Login(oauth2 -> oauth2.successHandler(handler));
            }
        }

        // CORS configuration
        if (properties.isCorsEnabled()) {
            http.cors(cors -> cors.configurationSource(corsConfigurationSource(properties)));
        }

        return http.build();
    }

    private CorsConfigurationSource corsConfigurationSource(SecurityStarterProperties properties) {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(properties.getCorsAllowedOrigins());
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));
        configuration.setAllowedHeaders(List.of("*"));
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
