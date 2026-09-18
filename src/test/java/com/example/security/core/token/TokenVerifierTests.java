package com.example.security.core.token;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.List;

import javax.crypto.SecretKey;

import com.example.security.core.support.TokenTestSupport;
import org.junit.jupiter.api.Test;

import org.springframework.security.oauth2.jwt.Jwt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class TokenVerifierTests {

	// Anchored to the real clock: the decoder validates expiry against the real system clock,
	// so a token issued at a hard coded past instant would read as expired for the wrong reason.
	private static final Instant NOW = Instant.now().truncatedTo(ChronoUnit.SECONDS);

	private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);

	private final TokenConfig config = TokenTestSupport.config(JwtAlgorithm.HS256);

	private final TokenService service = new TokenService(TokenTestSupport.hs256Encoder(), this.config, CLOCK);

	private final TokenVerifier verifier = new TokenVerifier(TokenTestSupport.hs256Decoder());

	@Test
	void acceptsAnAccessTokenWhereAnAccessTokenIsExpected() {
		IssuedToken issued = this.service.issueAccessToken("alice", List.of("ROLE_USER"));

		Jwt jwt = this.verifier.verifyType(issued.value(), TokenType.ACCESS);

		assertThat(jwt.getSubject()).isEqualTo("alice");
	}

	@Test
	void acceptsARefreshTokenWhereARefreshTokenIsExpected() {
		IssuedToken issued = this.service.issueRefreshToken("alice");

		Jwt jwt = this.verifier.verifyType(issued.value(), TokenType.REFRESH);

		assertThat(jwt.getSubject()).isEqualTo("alice");
	}

	@Test
	void rejectsAnAccessTokenPresentedAsARefreshToken() {
		IssuedToken issued = this.service.issueAccessToken("alice", List.of("ROLE_USER"));

		assertThatExceptionOfType(TokenValidationException.class)
			.isThrownBy(() -> this.verifier.verifyType(issued.value(), TokenType.REFRESH))
			.withMessageContaining("Expected a refresh token but received a access token");
	}

	@Test
	void rejectsARefreshTokenPresentedAsAnAccessToken() {
		IssuedToken issued = this.service.issueRefreshToken("alice");

		assertThatExceptionOfType(TokenValidationException.class)
			.isThrownBy(() -> this.verifier.verifyType(issued.value(), TokenType.ACCESS))
			.withMessageContaining("Expected a access token but received a refresh token");
	}

	@Test
	void rejectsATokenSignedWithADifferentKey() {
		SecretKey otherKey = TokenTestSupport.secretKey("a-completely-different-secret-value-9876543210");
		TokenService foreignIssuer = new TokenService(TokenTestSupport.hs256Encoder(otherKey), this.config, CLOCK);
		IssuedToken issued = foreignIssuer.issueAccessToken("mallory", List.of("ROLE_ADMIN"));

		// The token is genuinely well formed and valid under the key that signed it, so the only
		// possible reason for rejection below is that it was verified against the wrong key.
		assertThat(TokenTestSupport.hs256Decoder(otherKey).decode(issued.value()).getSubject()).isEqualTo("mallory");

		assertThatExceptionOfType(TokenValidationException.class).isThrownBy(() -> this.verifier.verify(issued.value()))
			.withMessageContaining("The token was rejected");
	}

	@Test
	void rejectsATokenThatHasAlreadyExpired() {
		// Issued two hours ago with a one minute lifetime: comfortably in the past.
		Clock past = Clock.fixed(NOW.minus(Duration.ofHours(2)), ZoneOffset.UTC);
		TokenConfig shortLived = new TokenConfig("https://issuer.test", "test-audience", JwtAlgorithm.HS256, "roles",
				Duration.ofMinutes(1), Duration.ofDays(7));
		TokenService expiredIssuer = new TokenService(TokenTestSupport.hs256Encoder(), shortLived, past);
		IssuedToken issued = expiredIssuer.issueAccessToken("alice", List.of("ROLE_USER"));

		assertThatExceptionOfType(TokenValidationException.class).isThrownBy(() -> this.verifier.verify(issued.value()));
	}

	@Test
	void rejectsGarbageAndBlankInput() {
		assertThatExceptionOfType(TokenValidationException.class).isThrownBy(() -> this.verifier.verify("not-a-jwt"));
		assertThatExceptionOfType(TokenValidationException.class).isThrownBy(() -> this.verifier.verify("   "))
			.withMessageContaining("No token was presented");
		assertThatExceptionOfType(TokenValidationException.class).isThrownBy(() -> this.verifier.verify(null));
	}

	@Test
	void rejectsATokenSignedWithAnAlgorithmThatIsNotConfigured() {
		// The decoder is pinned to HS256, so a token carrying no signature at all must not pass.
		String unsigned = "eyJhbGciOiJub25lIn0."
				+ java.util.Base64.getUrlEncoder()
					.withoutPadding()
					.encodeToString("{\"sub\":\"alice\"}".getBytes(StandardCharsets.UTF_8))
				+ ".";

		assertThatExceptionOfType(TokenValidationException.class).isThrownBy(() -> this.verifier.verify(unsigned));
	}

}
