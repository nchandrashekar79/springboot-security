package com.example.security.starter;

import java.util.List;

import com.example.security.core.revocation.RevocationRegistry;
import com.example.security.core.token.IssuedToken;
import com.example.security.core.token.TokenService;
import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Revocation is off by default, so it is switched on explicitly here and the real HTTP path is
 * exercised: a token that was valid a moment ago must stop working once revoked.
 */
@SpringBootTest(properties = "app.security.revocation.enabled=true")
@AutoConfigureMockMvc
class RevokedTokenTests {

	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private TokenService tokenService;

	@Autowired
	private RevocationRegistry revocationRegistry;

	@Test
	void acceptsATokenThatHasNotBeenRevoked() throws Exception {
		IssuedToken token = this.tokenService.issueAccessToken("alice", List.of("ROLE_USER"));

		this.mockMvc.perform(get("/protected").header("Authorization", "Bearer " + token.value()))
			.andExpect(status().isOk());
	}

	@Test
	void refusesARevokedToken() throws Exception {
		IssuedToken token = this.tokenService.issueAccessToken("alice", List.of("ROLE_USER"));

		this.mockMvc.perform(get("/protected").header("Authorization", "Bearer " + token.value()))
			.andExpect(status().isOk());

		this.revocationRegistry.revoke(token.tokenId(), token.expiresAt());

		this.mockMvc.perform(get("/protected").header("Authorization", "Bearer " + token.value()))
			.andExpect(status().isUnauthorized());
	}

	@Test
	void leavesOtherTokensAloneWhenOneIsRevoked() throws Exception {
		IssuedToken revoked = this.tokenService.issueAccessToken("alice", List.of("ROLE_USER"));
		IssuedToken untouched = this.tokenService.issueAccessToken("bob", List.of("ROLE_USER"));

		this.revocationRegistry.revoke(revoked.tokenId(), revoked.expiresAt());

		this.mockMvc.perform(get("/protected").header("Authorization", "Bearer " + revoked.value()))
			.andExpect(status().isUnauthorized());
		this.mockMvc.perform(get("/protected").header("Authorization", "Bearer " + untouched.value()))
			.andExpect(status().isOk());
	}

}
