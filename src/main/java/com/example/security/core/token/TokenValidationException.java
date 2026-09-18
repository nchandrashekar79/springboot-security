package com.example.security.core.token;

/**
 * Thrown when a token cannot be trusted: bad signature, expired, wrong issuer, or not the kind of
 * token the caller needed.
 */
public class TokenValidationException extends RuntimeException {

	private static final long serialVersionUID = 1L;

	public TokenValidationException(String message) {
		super(message);
	}

	public TokenValidationException(String message, Throwable cause) {
		super(message, cause);
	}
}
