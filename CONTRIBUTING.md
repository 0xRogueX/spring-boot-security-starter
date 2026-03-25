# Contributing to Spring Boot Security Starter

Thank you for your interest in contributing! This guide will help you get started.

## How to Contribute

### Reporting Issues

- Use [GitHub Issues](https://github.com/springsecuritystarter/spring-boot-security-starter/issues) to report bugs or request features
- Check existing issues before creating a new one
- Use the provided issue templates

### Pull Requests

1. **Fork** the repository
2. **Create a branch** from `main`: `git checkout -b feature/my-feature`
3. **Make your changes** with clear, descriptive commits
4. **Add tests** for any new functionality
5. **Run the test suite**: `mvn clean test`
6. **Submit a pull request** against `main`

### Code Standards

- **Java 17+** features are welcome
- Follow existing code style (no tabs, 4-space indentation)
- All public APIs must have Javadoc
- All new features must include unit tests
- Use constructor injection (no `@Autowired` on fields)
- Use `@ConditionalOnMissingBean` for all auto-configured beans

### Commit Messages

Use conventional commit format:
```
feat: add OAuth2 support
fix: correct token expiry calculation
docs: update configuration reference
test: add integration tests for refresh tokens
```

### Testing

```bash
# Run all tests
mvn clean test

# Run a specific module's tests
mvn clean test -pl spring-boot-security-starter

# Run a specific test class
mvn clean test -pl spring-boot-security-starter -Dtest=JwtTokenProviderTest
```

## Development Setup

1. Clone the repo: `git clone https://github.com/springsecuritystarter/spring-boot-security-starter.git`
2. Build: `mvn clean install`
3. Run example: `mvn spring-boot:run -pl examples/jwt-example`

## License

By contributing, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE).
