package com.example.security.core.token;

import java.util.Objects;

import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

/**
 * Verifies tokens that were issued elsewhere.
 *
 * <p>Signature, expiry, not-before and issuer checks are performed by the underlying
 * {@link JwtDecoder}; this class adds the check that callers so often forget, namely that a
 * refresh token must not be accepted where an access token is expected, and vice versa.
 */
public class TokenVerifier {

	private final JwtDecoder decoder;

	/**
	 * Create a verifier.
	 * @param decoder the decoder, configured with the verification key and claim validators
	 */
	public TokenVerifier(JwtDecoder decoder) {
		this.decoder = Objects.requireNonNull(decoder, "decoder must not be null");
	}

	/**
	 * Decode and validate a token.
	 * @param token the encoded token
	 * @return the validated JWT
	 * @throws TokenValidationException if the token is malformed, forged, expired or not yet valid
	 */
	public Jwt verify(String token) {
		if (token == null || token.isBlank()) {
			throw new TokenValidationException("No token was presented");
		}
		try {
			return this.decoder.decode(token);
		}
		catch (JwtException ex) {
			throw new TokenValidationException("The token was rejected: " + ex.getMessage(), ex);
		}
	}

	/**
	 * Decode a token and assert that it is of the expected type.
	 * @param token the encoded token
	 * @param expected the expected token type
	 * @return the validated JWT
	 * @throws TokenValidationException if validation fails or the token type does not match
	 */
	public Jwt verifyType(String token, TokenType expected) {
		Objects.requireNonNull(expected, "expected must not be null");
		Jwt jwt = verify(token);
		TokenType actual = TokenType.fromClaimValue(jwt.getClaimAsString(TokenType.CLAIM_NAME));
		if (actual != expected) {
			throw new TokenValidationException(
					"Expected a %s token but received %s".formatted(expected.claimValue(), describe(actual)));
		}
		return jwt;
	}

	private static String describe(TokenType actual) {
		return (actual == null) ? "a token with no declared type" : "a " + actual.claimValue() + " token";
	}
}
