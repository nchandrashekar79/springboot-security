package com.example.security.autoconfigure.jwt;

import java.util.List;

import com.example.security.autoconfigure.AppSecurityProperties;

import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;

/**
 * Builds the claim validators applied to every accepted token.
 *
 * <p>Validating the audience as well as the issuer matters: without it, a token minted for a
 * different application that happens to share the same signing key would be accepted here.
 */
final class TokenValidators {

	private TokenValidators() {
	}

	static OAuth2TokenValidator<Jwt> from(AppSecurityProperties properties) {
		AppSecurityProperties.Jwt jwt = properties.getJwt();
		OAuth2TokenValidator<Jwt> audience = new JwtClaimValidator<List<String>>(JwtClaimNames.AUD,
				(value) -> value != null && value.contains(jwt.getAudience()));
		return new DelegatingOAuth2TokenValidator<>(new JwtTimestampValidator(jwt.getClockSkew()),
				new JwtIssuerValidator(jwt.getIssuer()), audience);
	}

}
