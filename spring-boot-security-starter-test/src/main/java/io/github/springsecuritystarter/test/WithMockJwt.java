package io.github.springsecuritystarter.test;

import org.springframework.security.test.context.support.WithSecurityContext;

import java.lang.annotation.*;

/**
 * Test annotation that sets up a mock JWT-authenticated security context.
 * <p>
 * Use this annotation on test methods to simulate an authenticated user
 * with the specified username and roles.
 *
 * <h3>Usage</h3>
 * <pre>
 * &#64;Test
 * &#64;WithMockJwt(username = "admin", roles = {"ADMIN"})
 * void adminEndpoint_shouldSucceed() {
 *     // test runs as authenticated "admin" user with ROLE_ADMIN
 * }
 * </pre>
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
@WithSecurityContext(factory = WithMockJwtSecurityContextFactory.class)
public @interface WithMockJwt {

    /**
     * The username for the mock user. Default: "testuser".
     */
    String username() default "testuser";

    /**
     * The roles for the mock user (without the "ROLE_" prefix). Default: {"USER"}.
     */
    String[] roles() default {"USER"};
}
