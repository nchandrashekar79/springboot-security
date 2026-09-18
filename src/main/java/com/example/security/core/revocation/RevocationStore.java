package com.example.security.core.revocation;

/**
 * Read side of revocation: answers whether a token must no longer be honoured.
 *
 * <p>Access tokens are stateless, so a denylist entry can only be seen by a process that shares
 * the store. The default in-memory implementation therefore only protects a single JVM. A
 * deployment where revocation must be visible to every consumer should either point this SPI at a
 * shared store or use the remote introspection implementation, and should additionally keep access
 * token lifetimes short so that an un-revoked token has little time to be useful.
 *
 * <p>The write side lives in {@link RevocationRegistry}.
 */
public interface RevocationStore {

	/**
	 * Test whether a token has been revoked. Entries that have passed their own expiry are treated
	 * as absent, so an expired token is never reported as revoked.
	 * @param tokenId the {@code jti} claim of the token
	 * @return {@code true} if the token is revoked and still within its original lifetime
	 */
	boolean isRevoked(String tokenId);

	/**
	 * Drop entries that can no longer affect any decision.
	 */
	default void purgeExpired() {
	}

}
