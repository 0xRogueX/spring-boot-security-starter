# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- OAuth2 Identity Provider bridge (converts successful OAuth2 logins into native JWTs & Refresh Tokens)
- JWT authentication with configurable secret, expiration, and issuer
- Refresh token support with automatic rotation and revocation
- Role-based access control with default hierarchy (ADMIN > USER)
- Method-level security via `@EnableMethodSecurity`
- Global security exception handler with structured JSON responses
- Security audit logging for authentication events
- Configurable public paths, CORS, and security hardening defaults
- Spring Boot auto-configuration with `@ConditionalOnMissingBean` for full customization
- `@WithMockJwt` test annotation for easy JWT user mocking
- JWT example application
- RBAC example application
- GitHub Actions CI pipeline
- Apache 2.0 License

### Changed
- Refactored from tutorial-style demo into multi-module Maven starter library
- Renamed package from `com.example.securitydemo` to `io.github.springsecuritystarter`
- Replaced hardcoded secrets with externalized `spring.security.starter.jwt.*` properties
- Replaced `@Autowired` field injection with constructor injection throughout
- Replaced `System.out.println` debugging with SLF4J structured logging

### Removed
- 8 numbered tutorial directories (01-securitydemo through 08-jwt-authentication)
- Hardcoded demo users (`user1/password1`, `admin/adminPass`)
- `{noop}` plaintext password encoding
- H2 console unconditional permit
- Global CSRF disable (now only disabled for stateless API configurations)

## [1.0.0] - TBD

Initial release.
