package com.example.security.core.revocation;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class InMemoryRevocationStoreTests {

	private static final Instant NOW = Instant.parse("2026-01-01T10:00:00Z");

	private final Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);

	private final InMemoryRevocationStore store = new InMemoryRevocationStore(this.clock);

	@Test
	void reportsAnUnknownTokenAsNotRevoked() {
		assertThat(this.store.isRevoked("never-seen")).isFalse();
	}

	@Test
	void reportsARevokedTokenAsRevoked() {
		this.store.revoke("jti-1", NOW.plus(Duration.ofMinutes(15)));

		assertThat(this.store.isRevoked("jti-1")).isTrue();
	}

	@Test
	void treatsAnEntryPastItsOwnExpiryAsNotRevoked() {
		// Revoking a token that has already expired is meaningless, so the entry must not survive.
		this.store.revoke("jti-1", NOW.minus(Duration.ofSeconds(1)));

		assertThat(this.store.isRevoked("jti-1")).isFalse();
		assertThat(this.store.size()).isZero();
	}

	@Test
	void keepsAnEntryWhoseExpiryExactlyEqualsNowAsExpired() {
		this.store.revoke("jti-1", NOW);

		assertThat(this.store.isRevoked("jti-1")).isFalse();
	}

	@Test
	void ignoresBlankOrNullTokenIds() {
		this.store.revoke(null, NOW.plus(Duration.ofMinutes(5)));
		this.store.revoke("  ", NOW.plus(Duration.ofMinutes(5)));

		assertThat(this.store.size()).isZero();
		assertThat(this.store.isRevoked(null)).isFalse();
		assertThat(this.store.isRevoked("  ")).isFalse();
	}

	@Test
	void purgeExpiredDropsOnlyTheExpiredEntries() {
		this.store.revoke("live", NOW.plus(Duration.ofMinutes(15)));
		this.store.revoke("dead", NOW.minus(Duration.ofMinutes(1)));

		this.store.purgeExpired();

		assertThat(this.store.size()).isEqualTo(1);
		assertThat(this.store.purgedCount()).isEqualTo(1);
		assertThat(this.store.isRevoked("live")).isTrue();
	}

	@Test
	void revocationWithoutAnExpiryIsRetainedIndefinitely() {
		this.store.revoke("forever", null);

		assertThat(this.store.isRevoked("forever")).isTrue();
		this.store.purgeExpired();
		assertThat(this.store.isRevoked("forever")).isTrue();
	}

}
