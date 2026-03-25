package io.github.springsecuritystarter.example.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Demonstrates role hierarchy and method-level security.
 * <p>
 * The starter configures {@code ROLE_ADMIN > ROLE_USER} by default,
 * so admins can access user endpoints too.
 */
@RestController
@RequestMapping("/api")
public class RbacController {

    @GetMapping("/public")
    public Map<String, String> publicEndpoint() {
        return Map.of("message", "This endpoint is public");
    }

    @PreAuthorize("hasRole('USER')")
    @GetMapping("/user/data")
    public Map<String, Object> userData(Authentication auth) {
        return Map.of(
                "message", "User data accessible by USER and ADMIN (via hierarchy)",
                "user", auth.getName(),
                "authorities", auth.getAuthorities().toString()
        );
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin/data")
    public Map<String, Object> adminData(Authentication auth) {
        return Map.of(
                "message", "Admin data accessible only by ADMIN",
                "user", auth.getName(),
                "authorities", auth.getAuthorities().toString()
        );
    }

    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    @GetMapping("/shared")
    public Map<String, Object> sharedEndpoint(Authentication auth) {
        return Map.of(
                "message", "Shared endpoint using hasAnyRole",
                "user", auth.getName()
        );
    }
}
