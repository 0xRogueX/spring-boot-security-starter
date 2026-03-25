package io.github.springsecuritystarter.example.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Example protected endpoints demonstrating RBAC with the starter.
 */
@RestController
@RequestMapping("/api")
public class ProtectedController {

    @GetMapping("/hello")
    public Map<String, String> hello(Authentication authentication) {
        return Map.of(
                "message", "Hello, " + authentication.getName() + "!",
                "status", "authenticated"
        );
    }

    @PreAuthorize("hasRole('USER')")
    @GetMapping("/user/profile")
    public Map<String, Object> userProfile(Authentication authentication) {
        return Map.of(
                "username", authentication.getName(),
                "roles", authentication.getAuthorities(),
                "message", "This endpoint requires ROLE_USER"
        );
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin/dashboard")
    public Map<String, Object> adminDashboard(Authentication authentication) {
        return Map.of(
                "username", authentication.getName(),
                "roles", authentication.getAuthorities(),
                "message", "This endpoint requires ROLE_ADMIN"
        );
    }
}
