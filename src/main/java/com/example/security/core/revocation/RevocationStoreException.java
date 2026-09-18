package com.example.security.core.revocation;

/**
 * Thrown when a revocation store cannot answer, for example because a remote introspection
 * endpoint is unreachable.
 *
 * <p>Callers should treat this as a hard failure rather than assuming a token is good.
 */
public class RevocationStoreException extends RuntimeException {

	private static final long serialVersionUID = 1L;

	public RevocationStoreException(String message) {
		super(message);
	}

	public RevocationStoreException(String message, Throwable cause) {
		super(message, cause);
	}
}
