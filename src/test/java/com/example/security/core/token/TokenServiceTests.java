package com.example.security.core.token;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;

import com.example.security.core.support.TokenTestSupport;
import com.nimbusds.jose.jwk.RSAKey;
import org.junit.jupiter.api.Test;

import org.springframework.security.oauth2.jwt.Jwt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

class TokenServiceTests {

	// Anchored to the real clock, truncated to seconds because the JWT timestamps only carry
	// second precision. The decoders used below validate expiry against the real system clock,
	// so a token issued at a hard coded past instant would simply read as expired.
	private static final Instant NOW = Instant.now().truncatedTo(ChronoUnit.SECONDS);

	private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);

	@Test
	void issuesAccessTokenCarryingIssuerAudienceSubjectAndAuthorities() {
		TokenConfig config = TokenTestSupport.config(JwtAlgorithm.HS256);
		TokenService service = new TokenService(TokenTestSupport.hs256Encoder(), config, CLOCK);

		IssuedToken issued = service.issueAccessToken("alice", List.of("ROLE_USER", "ROLE_ADMIN"));

		Jwt jwt = TokenTestSupport.hs256Decoder().decode(issued.value());
		assertThat(jwt.getIssuer().toString()).isEqualTo("https://issuer.test");
		assertThat(jwt.getAudience()).containsExactly("test-audience");
		assertThat(jwt.getSubject()).isEqualTo("alice");
		assertThat(jwt.getClaimAsStringList("roles")).containsExactly("ROLE_USER", "ROLE_ADMIN");
		assertThat(jwt.getClaimAsString(TokenType.CLAIM_NAME)).isEqualTo("access");
		assertThat(jwt.getId()).isEqualTo(issued.tokenId());
		assertThat(jwt.getIssuedAt()).isEqualTo(NOW);
		assertThat(jwt.getExpiresAt()).isEqualTo(NOW.plus(Duration.ofMinutes(15)));
	}

	@Test
	void issuesRefreshTokenWithRefreshTypeAndItsOwnLifetime() {
		TokenConfig config = TokenTestSupport.config(JwtAlgorithm.HS256);
		TokenService service = new TokenService(TokenTestSupport.hs256Encoder(), config, CLOCK);

		IssuedToken issued = service.issueRefreshToken("alice");

		Jwt jwt = TokenTestSupport.hs256Decoder().decode(issued.value());
		assertThat(jwt.getClaimAsString(TokenType.CLAIM_NAME)).isEqualTo("refresh");
		assertThat(issued.type()).isEqualTo(TokenType.REFRESH);
		assertThat(jwt.getExpiresAt()).isEqualTo(NOW.plus(Duration.ofDays(7)));
	}

	@Test
	void mergesAdditionalClaimsIntoTheAccessToken() {
		TokenConfig config = TokenTestSupport.config(JwtAlgorithm.HS256);
		TokenService service = new TokenService(TokenTestSupport.hs256Encoder(), config, CLOCK);

		IssuedToken issued = service.issueAccessToken("alice", List.of("ROLE_USER"), Map.of("tenant", "acme"));

		Jwt jwt = TokenTestSupport.hs256Decoder().decode(issued.value());
		assertThat(jwt.getClaimAsString("tenant")).isEqualTo("acme");
		assertThat(jwt.getClaimAsStringList("roles")).containsExactly("ROLE_USER");
	}

	@Test
	void issuesVerifiableTokensSignedWithRsa() {
		RSAKey key = TokenTestSupport.rsaKey();
		TokenConfig config = TokenTestSupport.config(JwtAlgorithm.RS256);
		TokenService service = new TokenService(TokenTestSupport.rs256Encoder(key), config, CLOCK);

		IssuedToken issued = service.issueAccessToken("alice", List.of("ROLE_USER"));

		Jwt jwt = TokenTestSupport.rs256Decoder(key).decode(issued.value());
		assertThat(jwt.getSubject()).isEqualTo("alice");
		assertThat(jwt.getClaimAsString(TokenType.CLAIM_NAME)).isEqualTo("access");
	}

	@Test
	void assignsADistinctTokenIdPerToken() {
		TokenConfig config = TokenTestSupport.config(JwtAlgorithm.HS256);
		TokenService service = new TokenService(TokenTestSupport.hs256Encoder(), config, CLOCK);

		IssuedToken first = service.issueAccessToken("alice", List.of("ROLE_USER"));
		IssuedToken second = service.issueAccessToken("alice", List.of("ROLE_USER"));

		assertThat(first.tokenId()).isNotEqualTo(second.tokenId());
		assertThat(first.value()).isNotEqualTo(second.value());
	}

	@Test
	void reportsRemainingLifetimeInSeconds() {
		TokenConfig config = TokenTestSupport.config(JwtAlgorithm.HS256);
		TokenService service = new TokenService(TokenTestSupport.hs256Encoder(), config, CLOCK);

		IssuedToken issued = service.issueAccessToken("alice", List.of("ROLE_USER"));

		assertThat(issued.expiresInSeconds(CLOCK)).isEqualTo(Duration.ofMinutes(15).toSeconds());
	}

	@Test
	void refusesABlankSubject() {
		TokenConfig config = TokenTestSupport.config(JwtAlgorithm.HS256);
		TokenService service = new TokenService(TokenTestSupport.hs256Encoder(), config, CLOCK);

		assertThatIllegalArgumentException().isThrownBy(() -> service.issueAccessToken("  ", List.of()));
	}

	@Test
	void refusesToBeConstructedWithoutAnEncoder() {
		TokenConfig config = TokenTestSupport.config(JwtAlgorithm.HS256);

		assertThatExceptionOfType(NullPointerException.class).isThrownBy(() -> new TokenService(null, config));
	}

}
