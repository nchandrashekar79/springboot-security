package com.example.security.starter;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.example.security.core.token.IssuedToken;
import com.example.security.core.token.TokenConfig;
import com.example.security.core.token.TokenService;
import com.nimbusds.jose.jwk.source.ImmutableSecret;
import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Proves that adding this library to an ordinary Spring Boot application is enough to get working
 * bearer-token security, by exercising the real filter chain over HTTP.
 */
@SpringBootTest
@AutoConfigureMockMvc
class StarterConsumerTests {

	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private TokenService tokenService;

	@Autowired
	private TokenConfig tokenConfig;

	@Autowired
	private JwtEncoder jwtEncoder;

	@Autowired
	private JwtDecoder jwtDecoder;

	@Autowired
	private JwtAuthenticationConverter jwtAuthenticationConverter;

	@Test
	void servesAConfiguredOpenPathWithoutAToken() throws Exception {
		this.mockMvc.perform(get("/open")).andExpect(status().isOk()).andExpect(content().string("open"));
	}

	@Test
	void refusesAProtectedPathWithoutATokenAndSaysHowToAuthenticate() throws Exception {
		this.mockMvc.perform(get("/protected"))
			.andExpect(status().isUnauthorized())
			.andExpect(header().string("WWW-Authenticate", "Bearer"))
			.andExpect(jsonPath("$.error").value("unauthorized"));
	}

	@Test
	void refusesAnUnlistedPathRatherThanFallingBackToPermitAll() throws Exception {
		// /staff is not in permit-paths, so the catch-all must require authentication.
		this.mockMvc.perform(get("/staff")).andExpect(status().isUnauthorized());
	}

	@Test
	void acceptsATokenIssuedByTheLibrary() throws Exception {
		IssuedToken token = this.tokenService.issueAccessToken("alice", List.of("ROLE_USER"));

		this.mockMvc.perform(get("/protected").header("Authorization", bearer(token)))
			.andExpect(status().isOk())
			.andExpect(content().string("protected"));
	}

	@Test
	void mapsIssuedAuthoritiesBackToTheSameGrantedAuthorities() {
		// The issuer writes authority strings verbatim, so the reader must not add a prefix of its
		// own. If it did, ROLE_STAFF would become ROLE_ROLE_STAFF and every hasRole check would
		// fail with a 403 that looks like a missing role rather than a mapping mistake.
		IssuedToken token = this.tokenService.issueAccessToken("bob", List.of("ROLE_STAFF", "SCOPE_read"));
		Jwt jwt = this.jwtDecoder.decode(token.value());

		List<String> authorities = this.jwtAuthenticationConverter.convert(jwt)
			.getAuthorities()
			.stream()
			.map(GrantedAuthority::getAuthority)
			.toList();

		// Spring Security adds marker authorities of its own (FACTOR_BEARER), so this asserts the
		// issued authorities survived rather than that they are the only ones present.
		assertThat(authorities).contains("ROLE_STAFF", "SCOPE_read")
			.doesNotContain("ROLE_ROLE_STAFF", "ROLE_SCOPE_read");
	}

	@Test
	void refusesATokenSignedWithADifferentKey() throws Exception {
		IssuedToken forged = forgeToken("mallory", "a-different-secret-value-long-enough-1234567890");

		this.mockMvc.perform(get("/protected").header("Authorization", bearer(forged)))
			.andExpect(status().isUnauthorized());
	}

	@Test
	void refusesAnExpiredToken() throws Exception {
		IssuedToken expired = new TokenService(this.jwtEncoder, this.tokenConfig,
				Clock.fixed(Instant.now().minus(Duration.ofHours(2)), ZoneOffset.UTC))
			.issueAccessToken("alice", List.of("ROLE_USER"));

		this.mockMvc.perform(get("/protected").header("Authorization", bearer(expired)))
			.andExpect(status().isUnauthorized());
	}

	@Test
	void refusesARefreshTokenUsedAsABearerToken() throws Exception {
		// The refresh token is genuinely valid and longer lived, so without the token type check it
		// would unlock every protected endpoint.
		IssuedToken refreshToken = this.tokenService.issueRefreshToken("alice");

		this.mockMvc.perform(get("/protected").header("Authorization", bearer(refreshToken)))
			.andExpect(status().isUnauthorized());
	}

	@Test
	void refusesGarbage() throws Exception {
		this.mockMvc.perform(get("/protected").header("Authorization", "Bearer not-a-token"))
			.andExpect(status().isUnauthorized());
	}

	@Test
	void enforcesARuleAddedByAnAuthorizationCustomizer() throws Exception {
		IssuedToken ordinaryUser = this.tokenService.issueAccessToken("alice", List.of("ROLE_USER"));

		this.mockMvc.perform(get("/staff").header("Authorization", bearer(ordinaryUser)))
			.andExpect(status().isForbidden())
			.andExpect(jsonPath("$.error").value("forbidden"));
	}

	@Test
	void allowsARuleAddedByAnAuthorizationCustomizerToBeSatisfied() throws Exception {
		IssuedToken staff = this.tokenService.issueAccessToken("bob", List.of("ROLE_STAFF"));

		this.mockMvc.perform(get("/staff").header("Authorization", bearer(staff)))
			.andExpect(status().isOk())
			.andExpect(content().string("staff"));
	}

	@Test
	void enforcesMethodSecurity() throws Exception {
		IssuedToken ordinaryUser = this.tokenService.issueAccessToken("alice", List.of("ROLE_USER"));

		this.mockMvc.perform(get("/admin").header("Authorization", bearer(ordinaryUser)))
			.andExpect(status().isForbidden())
			.andExpect(jsonPath("$.error").value("forbidden"));
	}

	@Test
	void allowsMethodSecurityToBeSatisfied() throws Exception {
		IssuedToken administrator = this.tokenService.issueAccessToken("carol", List.of("ROLE_ADMIN"));

		this.mockMvc.perform(get("/admin").header("Authorization", bearer(administrator)))
			.andExpect(status().isOk())
			.andExpect(content().string("admin"));
	}

	private static String bearer(IssuedToken token) {
		return "Bearer " + token.value();
	}

	private IssuedToken forgeToken(String subject, String secret) {
		SecretKey key = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
		TokenService forger = new TokenService(new NimbusJwtEncoder(new ImmutableSecret<>(key)), this.tokenConfig);
		return forger.issueAccessToken(subject, List.of("ROLE_ADMIN"));
	}

}
