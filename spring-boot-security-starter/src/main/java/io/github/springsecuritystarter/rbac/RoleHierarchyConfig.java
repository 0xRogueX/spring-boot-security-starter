package io.github.springsecuritystarter.rbac;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;

/**
 * Default role hierarchy configuration.
 * <p>
 * Establishes a standard role hierarchy: {@code ROLE_ADMIN > ROLE_USER}.
 * This means any user with {@code ROLE_ADMIN} also has {@code ROLE_USER} privileges.
 * <p>
 * To customize the hierarchy, define your own {@link RoleHierarchy} bean:
 * <pre>
 * &#64;Bean
 * public RoleHierarchy roleHierarchy() {
 *     return RoleHierarchyImpl.fromHierarchy("ROLE_SUPER_ADMIN > ROLE_ADMIN > ROLE_USER");
 * }
 * </pre>
 */
@Configuration
public class RoleHierarchyConfig {

    @Bean
    @ConditionalOnMissingBean
    public RoleHierarchy roleHierarchy() {
        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        roleHierarchy.setHierarchy("ROLE_ADMIN > ROLE_USER");
        return roleHierarchy;
    }

    @Bean
    @ConditionalOnMissingBean
    public MethodSecurityExpressionHandler methodSecurityExpressionHandler(RoleHierarchy roleHierarchy) {
        DefaultMethodSecurityExpressionHandler handler = new DefaultMethodSecurityExpressionHandler();
        handler.setRoleHierarchy(roleHierarchy);
        return handler;
    }
}
