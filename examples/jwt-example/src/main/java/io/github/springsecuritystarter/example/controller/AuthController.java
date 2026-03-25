package io.github.springsecuritystarter.example.controller;

import io.github.springsecuritystarter.auth.AuthenticationService;
import io.github.springsecuritystarter.auth.dto.LoginRequest;
import io.github.springsecuritystarter.auth.dto.LoginResponse;
import io.github.springsecuritystarter.auth.dto.RefreshTokenRequest;
import io.github.springsecuritystarter.auth.dto.RefreshTokenResponse;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

/**
 * Example authentication controller showing how to use the starter's
 * {@link AuthenticationService} for login, refresh, and logout.
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthenticationService authenticationService;

    public AuthController(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest request) {
        LoginResponse response = authenticationService.authenticate(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/refresh")
    public ResponseEntity<RefreshTokenResponse> refresh(@Valid @RequestBody RefreshTokenRequest request) {
        RefreshTokenResponse response = authenticationService.refresh(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(Principal principal) {
        authenticationService.logout(principal.getName());
        return ResponseEntity.ok().build();
    }
}
