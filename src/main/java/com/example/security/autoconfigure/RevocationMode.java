package com.example.security.autoconfigure;

/**
 * Where revocation decisions come from.
 */
public enum RevocationMode {

	/**
	 * Decisions are held in this JVM. Only correct when the same process both issues and consumes
	 * the tokens, because a revocation recorded by one process is invisible to every other.
	 */
	LOCAL,

	/**
	 * Decisions are requested from the token issuer. Required when several applications must agree
	 * on what has been revoked.
	 */
	REMOTE

}
