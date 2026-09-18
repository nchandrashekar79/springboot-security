package com.example.security.core.revocation;

import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Revocation store backed by a map in this JVM.
 *
 * <p>This is the default because it needs no infrastructure, and it is sufficient when a single
 * application both issues and consumes its tokens. It is <em>not</em> sufficient when several
 * applications must agree on what has been revoked, because each JVM keeps its own copy: a token
 * revoked by the authentication server stays valid in every consumer until it expires. Use a
 * shared store or remote introspection in that situation.
 */
public class InMemoryRevocationStore implements RevocationRegistry {

	private final Map<String, Instant> revoked = new ConcurrentHashMap<>();

	private final AtomicLong purged = new AtomicLong();

	private final Clock clock;

	/**
	 * Create a store that reads the current time from the system clock.
	 */
	public InMemoryRevocationStore() {
		this(Clock.systemUTC());
	}

	/**
	 * Create a store with an explicit clock.
	 * @param clock the clock used to decide whether an entry is still relevant
	 */
	public InMemoryRevocationStore(Clock clock) {
		this.clock = Objects.requireNonNull(clock, "clock must not be null");
	}

	@Override
	public void revoke(String tokenId, Instant expiresAt) {
		if (tokenId == null || tokenId.isBlank()) {
			return;
		}
		this.revoked.put(tokenId, (expiresAt != null) ? expiresAt : Instant.MAX);
	}

	@Override
	public boolean isRevoked(String tokenId) {
		if (tokenId == null || tokenId.isBlank()) {
			return false;
		}
		Instant expiresAt = this.revoked.get(tokenId);
		if (expiresAt == null) {
			return false;
		}
		if (!expiresAt.isAfter(this.clock.instant())) {
			this.revoked.remove(tokenId);
			return false;
		}
		return true;
	}

	@Override
	public void purgeExpired() {
		Instant now = this.clock.instant();
		this.revoked.entrySet().removeIf((entry) -> {
			boolean expired = !entry.getValue().isAfter(now);
			if (expired) {
				this.purged.incrementAndGet();
			}
			return expired;
		});
	}

	/**
	 * Number of entries currently held, including entries for tokens that have since expired.
	 * @return the entry count
	 */
	public int size() {
		return this.revoked.size();
	}

	/**
	 * Number of entries discarded because their token had expired.
	 * @return the count of discarded entries
	 */
	public long purgedCount() {
		return this.purged.get();
	}
}
