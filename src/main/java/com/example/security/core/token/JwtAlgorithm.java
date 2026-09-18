package com.example.security.core.token;

/**
 * Signing algorithm used for the tokens issued and verified by this library.
 *
 * <p>{@link #HS256} relies on a shared secret and is intended for local development, where the
 * authentication server and the consuming application run on the same machine. {@link #RS256}
 * should be preferred whenever the authentication server and the consumers are deployed
 * separately, because consumers then only ever hold a public key.
 */
public enum JwtAlgorithm {

	/**
	 * HMAC using SHA-256. Requires a shared secret of at least 256 bits.
	 */
	HS256("HmacSHA256", true),

	/**
	 * RSASSA-PKCS1-v1_5 using SHA-256. Requires a private key to issue and a public key to verify.
	 */
	RS256("RSA", false);

	private final String keyAlgorithm;

	private final boolean symmetric;

	JwtAlgorithm(String keyAlgorithm, boolean symmetric) {
		this.keyAlgorithm = keyAlgorithm;
		this.symmetric = symmetric;
	}

	/**
	 * The {@code java.security} algorithm name used when building the key material.
	 * @return the JCA key algorithm name
	 */
	public String keyAlgorithm() {
		return this.keyAlgorithm;
	}

	/**
	 * Whether the same key is used to issue and to verify tokens.
	 * @return {@code true} for algorithms that use a shared secret
	 */
	public boolean isSymmetric() {
		return this.symmetric;
	}
}
