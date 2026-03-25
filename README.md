# Spring Boot Security Starter

[![Build Status](https://github.com/0xRogueX/spring-boot-security-starter/actions/workflows/ci.yml/badge.svg)](https://github.com/0xRogueX/spring-boot-security-starter/actions)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Java](https://img.shields.io/badge/Java-17%2B-orange.svg)](https://openjdk.org/)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.2.x-brightgreen.svg)](https://spring.io/projects/spring-boot)

A production-ready Spring Boot starter that adds **JWT authentication**, **OAuth2 Login Bridging**, **refresh tokens**, **role-based access control**, **method security**, **audit logging**, and **security hardening** to any Spring Boot application with minimal configuration.

---

## Why This Starter?

* Eliminates repetitive Spring Security boilerplate
* Provides a complete JWT + OAuth2 solution out of the box
* Designed for real-world backend applications
* Fully customizable and extensible

Built to help developers focus on business logic instead of security setup.

---

## Roadmap

* Publish to Maven Central
* Add production-ready sample applications
* Improve extensibility for enterprise use cases

---

## Problem

Every Spring Boot project that needs API security ends up copying the same boilerplate: JWT filter chains, token utilities, authentication entry points, password encoders, exception handlers, and messy OAuth2-to-JWT redirect logic. This starter eliminates that boilerplate.

## Solution

Add one dependency and configure your secret key. You get:

- **JWT Authentication** — access token generation, validation, and parsing
- **OAuth2 Login Bridge** — Seamlessly converts Google/GitHub logins into native JWTs
- **Refresh Tokens** — token rotation with automatic revocation
- **Role-Based Access Control** — role hierarchy (`ADMIN > USER`) with method security
- **Security Hardening** — stateless sessions, BCrypt passwords, structured 401/403 responses
- **Audit Logging** — login success/failure events logged automatically
- **Global Exception Handling** — consistent JSON error responses
- **100% Configurable** — every setting externalized via `application.yml`
- **100% Overridable** — every bean uses `@ConditionalOnMissingBean`

---

## Quick Start

### 1. Add the dependency

```xml
<dependency>
    <groupId>io.github.0xroguex</groupId>
    <artifactId>spring-boot-security-starter</artifactId>
    <version>1.0.0-SNAPSHOT</version>
</dependency>
```

### 2. Configure your `application.yml`

```yaml
spring:
  security:
    starter:
      jwt:
        secret: "YOUR_BASE64_ENCODED_SECRET_KEY"  # Required
        expiration: 3600000                         # 1 hour (default)
        refresh-expiration: 86400000                # 24 hours (default)
        issuer: "my-app"
      public-paths:
        - /api/auth/login
        - /api/auth/refresh
      audit-enabled: true
```

### 3. (Optional) Enable OAuth2 Login

Allow users to login via standard OAuth2 providers and natively return your JWT:

```yaml
spring:
  security:
    oauth2:
      client:
        registration:
          github:
            client-id: "your-github-client-id"
            client-secret: "your-github-client-secret"
    starter:
      oauth2:
        enabled: true
        success-redirect-uri: "http://localhost:3000/oauth2/redirect" # We will append ?accessToken=...
```

### 4. Provide a `UserDetailsService` (For standard login)

```java
@Bean
public UserDetailsService userDetailsService(PasswordEncoder passwordEncoder) {
    UserDetails user = User.builder()
            .username("admin")
            .password(passwordEncoder.encode("secret"))
            .roles("ADMIN")
            .build();
    return new InMemoryUserDetailsManager(user);
}
```

### 5. Secure your endpoints

```java
@PreAuthorize("hasRole('ADMIN')")
@GetMapping("/admin/dashboard")
public String admin() {
    return "Admin only";
}
```

**That's it.** The starter auto-configures the JWT filter chain, password encoder, authentication manager, exception handler, audit logger, and OAuth2 Success Handler.

---

## Configuration Reference

| Property | Default | Description |
|----------|---------|-------------|
| `spring.security.starter.jwt.secret` | — | **Required.** Base64-encoded HMAC signing key |
| `spring.security.starter.jwt.expiration` | `3600000` | Access token TTL in ms (1 hour) |
| `spring.security.starter.jwt.refresh-expiration` | `86400000` | Refresh token TTL in ms (24 hours) |
| `spring.security.starter.jwt.header` | `Authorization` | HTTP header for JWT |
| `spring.security.starter.jwt.prefix` | `Bearer ` | Token prefix in header |
| `spring.security.starter.jwt.issuer` | `spring-security-starter` | JWT issuer claim |
| `spring.security.starter.public-paths` | `[]` | Paths to permit without auth |
| `spring.security.starter.cors-enabled` | `false` | Enable CORS |
| `spring.security.starter.cors-allowed-origins` | `[]` | Allowed CORS origins |
| `spring.security.starter.audit-enabled` | `true` | Enable audit logging |
| `spring.security.starter.oauth2.enabled` | `false` | Enable OAuth2 login bridge |
| `spring.security.starter.oauth2.success-redirect-uri` | `http://localhost:3000/oauth2/redirect` | Frontend redirect URI after OAuth2 login |

---

## Architecture

```
spring-boot-security-starter/
├── autoconfigure/          Auto-configuration & properties
├── jwt/                    Token provider, filter, entry point
├── auth/                   AuthenticationService, RefreshTokenService, OAuth2 Handler
│   ├── dto/                LoginRequest, LoginResponse, RefreshToken DTOs
│   └── model/              RefreshToken model
├── rbac/                   Role hierarchy configuration
├── exception/              Exception handler & custom exceptions
└── audit/                  Security event audit logger
```

## Customization

Every bean is registered with `@ConditionalOnMissingBean`. To override any component, simply define your own bean:

```java
// Custom JWT token provider
@Bean
public JwtTokenProvider jwtTokenProvider(JwtProperties props) {
    return new MyCustomTokenProvider(props);
}
```

---

## Examples

See the [`examples/`](examples/) directory:

- **[jwt-example](examples/jwt-example/)** — Full JWT login + refresh + role-based access
- **[rbac-example](examples/rbac-example/)** — Role hierarchy and method-level security
- **[oauth2-example](examples/oauth2-example/)** — Google/GitHub login bridged to JWT

Run an example:
```bash
mvn spring-boot:run -pl examples/oauth2-example
```

---

## Building from Source

```bash
git clone https://github.com/0xRogueX/spring-boot-security-starter.git
cd spring-boot-security-starter
mvn clean install
```

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

This project is licensed under the [Apache License 2.0](LICENSE).
