package io.github.springsecuritystarter.exception;

/**
 * Thrown when a JWT token is malformed, has an invalid signature,
 * or is otherwise not parseable.
 */
public class InvalidTokenException extends RuntimeException {

    public InvalidTokenException(String message) {
        super(message);
    }

    public InvalidTokenException(String message, Throwable cause) {
        super(message, cause);
    }
}
