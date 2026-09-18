package com.example.security.core.token;

import java.time.Duration;
import java.util.Objects;

/**
 * The token shape shared by everything that issues tokens.
 *
 * <p>Kept free of Spring types so that the auto-configuration module owns the translation from
 * {@code app.security.*} properties to this object.
 *
 * @param issuer the {@code iss} claim written into every token
 * @param audience the single {@code aud} value written into every token
 * @param algorithm the signing algorithm
 * @param authoritiesClaim the claim holding the caller's authorities
 * @param accessTokenTtl lifetime of an access token
 * @param refreshTokenTtl lifetime of a refresh token
 */
public record TokenConfig(String issuer, String audience, JwtAlgorithm algorithm, String authoritiesClaim,
		Duration accessTokenTtl, Duration refreshTokenTtl) {

	public TokenConfig {
		Objects.requireNonNull(issuer, "issuer must not be null");
		Objects.requireNonNull(audience, "audience must not be null");
		Objects.requireNonNull(algorithm, "algorithm must not be null");
		Objects.requireNonNull(authoritiesClaim, "authoritiesClaim must not be null");
		Objects.requireNonNull(accessTokenTtl, "accessTokenTtl must not be null");
		Objects.requireNonNull(refreshTokenTtl, "refreshTokenTtl must not be null");
		if (issuer.isBlank()) {
			throw new IllegalArgumentException("issuer must not be blank");
		}
		if (audience.isBlank()) {
			throw new IllegalArgumentException("audience must not be blank");
		}
		if (authoritiesClaim.isBlank()) {
			throw new IllegalArgumentException("authoritiesClaim must not be blank");
		}
		if (accessTokenTtl.isNegative() || accessTokenTtl.isZero()) {
			throw new IllegalArgumentException("accessTokenTtl must be positive");
		}
		if (refreshTokenTtl.isNegative() || refreshTokenTtl.isZero()) {
			throw new IllegalArgumentException("refreshTokenTtl must be positive");
		}
	}
}
