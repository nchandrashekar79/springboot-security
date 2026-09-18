package com.example.security.core.token;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;

/**
 * Issues access and refresh tokens.
 *
 * <p>Instances are immutable and safe to share.
 */
public class TokenService {

	private final JwtEncoder encoder;

	private final TokenConfig config;

	private final Clock clock;

	/**
	 * Create a service that timestamps tokens using the system clock.
	 * @param encoder the encoder, configured with the signing key
	 * @param config the token shape
	 */
	public TokenService(JwtEncoder encoder, TokenConfig config) {
		this(encoder, config, Clock.systemUTC());
	}

	/**
	 * Create a service with an explicit clock, which makes expiry testable.
	 * @param encoder the encoder, configured with the signing key
	 * @param config the token shape
	 * @param clock the clock used for the {@code iat} and {@code exp} claims
	 */
	public TokenService(JwtEncoder encoder, TokenConfig config, Clock clock) {
		this.encoder = Objects.requireNonNull(encoder, "encoder must not be null");
		this.config = Objects.requireNonNull(config, "config must not be null");
		this.clock = Objects.requireNonNull(clock, "clock must not be null");
	}

	/**
	 * Issue an access token for a subject.
	 * @param subject the principal name, written to the {@code sub} claim
	 * @param authorities the authorities, written to the configured authorities claim
	 * @return the issued token
	 */
	public IssuedToken issueAccessToken(String subject, Collection<String> authorities) {
		return issueAccessToken(subject, authorities, Map.of());
	}

	/**
	 * Issue an access token carrying extra claims.
	 * @param subject the principal name, written to the {@code sub} claim
	 * @param authorities the authorities, written to the configured authorities claim
	 * @param additionalClaims claims to merge into the token, for example a tenant identifier
	 * @return the issued token
	 */
	public IssuedToken issueAccessToken(String subject, Collection<String> authorities,
			Map<String, Object> additionalClaims) {
		Map<String, Object> claims = new LinkedHashMap<>(additionalClaims);
		claims.put(this.config.authoritiesClaim(),
				List.copyOf(Objects.requireNonNull(authorities, "authorities must not be null")));
		return issue(subject, TokenType.ACCESS, this.config.accessTokenTtl(), claims);
	}

	/**
	 * Issue a refresh token for a subject.
	 * @param subject the principal name, written to the {@code sub} claim
	 * @return the issued token
	 */
	public IssuedToken issueRefreshToken(String subject) {
		return issue(subject, TokenType.REFRESH, this.config.refreshTokenTtl(), Map.of());
	}

	private IssuedToken issue(String subject, TokenType type, Duration ttl, Map<String, Object> claims) {
		if (subject == null || subject.isBlank()) {
			throw new IllegalArgumentException("subject must not be blank");
		}
		Instant issuedAt = this.clock.instant();
		Instant expiresAt = issuedAt.plus(ttl);
		String tokenId = newTokenId();

		JwtClaimsSet.Builder builder = JwtClaimsSet.builder()
			.issuer(this.config.issuer())
			.audience(List.of(this.config.audience()))
			.subject(subject)
			.issuedAt(issuedAt)
			.expiresAt(expiresAt)
			.id(tokenId)
			.claim(TokenType.CLAIM_NAME, type.claimValue());
		claims.forEach(builder::claim);

		String value = this.encoder.encode(JwtEncoderParameters.from(jwsHeader(), builder.build())).getTokenValue();
		return new IssuedToken(value, tokenId, type, issuedAt, expiresAt);
	}

	private JwsHeader jwsHeader() {
		return switch (this.config.algorithm()) {
			case HS256 -> JwsHeader.with(MacAlgorithm.HS256).build();
			case RS256 -> JwsHeader.with(SignatureAlgorithm.RS256).build();
		};
	}

	private static String newTokenId() {
		// UUID.randomUUID() is backed by a cryptographically strong generator, which matters
		// because the jti is what revocation decisions are keyed on.
		return UUID.randomUUID().toString();
	}
}
