package com.example.security.core.token;

/**
 * Distinguishes the two kinds of token issued by the authentication server.
 *
 * <p>Every issued token carries its type in the {@value #CLAIM_NAME} claim. The authentication
 * server refuses to exchange a token for a new one unless the presented token is of type
 * {@link #REFRESH}, which stops an access token from being used to mint fresh credentials.
 */
public enum TokenType {

	/**
	 * Short lived credential presented as a bearer token on protected endpoints.
	 */
	ACCESS("access"),

	/**
	 * Long lived credential accepted only by the token refresh endpoint.
	 */
	REFRESH("refresh");

	/**
	 * Claim holding the {@link TokenType} value. Deliberately not named {@code typ}, because that
	 * name refers to the JOSE protected header (RFC 7515) rather than a claim set member.
	 */
	public static final String CLAIM_NAME = "token_type";

	private final String claimValue;

	TokenType(String claimValue) {
		this.claimValue = claimValue;
	}

	/**
	 * The value written into the {@value #CLAIM_NAME} claim.
	 * @return the claim value
	 */
	public String claimValue() {
		return this.claimValue;
	}

	/**
	 * Resolve a token type from its claim value.
	 * @param claimValue the value read from the {@value #CLAIM_NAME} claim, may be {@code null}
	 * @return the matching token type, or {@code null} when the value is absent or unknown
	 */
	public static TokenType fromClaimValue(String claimValue) {
		if (claimValue == null) {
			return null;
		}
		for (TokenType candidate : values()) {
			if (candidate.claimValue.equals(claimValue)) {
				return candidate;
			}
		}
		return null;
	}
}
