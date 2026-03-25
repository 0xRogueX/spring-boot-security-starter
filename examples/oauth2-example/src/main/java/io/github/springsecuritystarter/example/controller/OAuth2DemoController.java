package io.github.springsecuritystarter.example.controller;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class OAuth2DemoController {

    @GetMapping("/api/me")
    public Map<String, Object> userDetails(Authentication authentication) {
        return Map.of(
                "subject", authentication.getName(),
                "authorities", authentication.getAuthorities().toString()
        );
    }
}
