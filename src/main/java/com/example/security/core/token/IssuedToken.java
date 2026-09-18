package com.example.security.core.token;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

/**
 * A freshly minted token together with the metadata a caller needs to hand it out.
 *
 * @param value the encoded JWT
 * @param tokenId the {@code jti} claim, used as the key when revoking the token
 * @param type whether this is an access token or a refresh token
 * @param issuedAt the {@code iat} claim
 * @param expiresAt the {@code exp} claim
 */
public record IssuedToken(String value, String tokenId, TokenType type, Instant issuedAt, Instant expiresAt) {

	public IssuedToken {
		Objects.requireNonNull(value, "value must not be null");
		Objects.requireNonNull(tokenId, "tokenId must not be null");
		Objects.requireNonNull(type, "type must not be null");
		Objects.requireNonNull(issuedAt, "issuedAt must not be null");
		Objects.requireNonNull(expiresAt, "expiresAt must not be null");
	}

	/**
	 * Remaining lifetime expressed the way OAuth 2.0 token responses express it.
	 * @return seconds until {@link #expiresAt()}, never negative
	 */
	public long expiresInSeconds() {
		return expiresInSeconds(Clock.systemUTC());
	}

	/**
	 * Remaining lifetime relative to a supplied clock.
	 * @param clock the clock to measure against
	 * @return seconds until {@link #expiresAt()}, never negative
	 */
	public long expiresInSeconds(Clock clock) {
		Objects.requireNonNull(clock, "clock must not be null");
		long remaining = Duration.between(clock.instant(), this.expiresAt).toSeconds();
		return Math.max(remaining, 0);
	}
}
