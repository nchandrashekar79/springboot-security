package com.example.security.core.revocation;

import java.time.Instant;

/**
 * Write side of revocation, held by the component that issues tokens.
 *
 * <p>Keeping this separate from {@link RevocationStore} means a consuming application can be given
 * the ability to <em>observe</em> revocation without being able to <em>perform</em> it. A consumer
 * that held the write side would be a second source of revocation truth, which is exactly the
 * situation a shared revocation store is meant to avoid.
 */
public interface RevocationRegistry extends RevocationStore {

	/**
	 * Record a token as revoked.
	 * @param tokenId the {@code jti} claim of the token
	 * @param expiresAt when the token would have expired anyway, after which the entry is obsolete;
	 * may be {@code null} to keep the entry indefinitely
	 */
	void revoke(String tokenId, Instant expiresAt);

}
