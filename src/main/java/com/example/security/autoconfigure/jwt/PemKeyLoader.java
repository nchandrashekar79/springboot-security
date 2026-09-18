package com.example.security.autoconfigure.jwt;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import org.springframework.core.io.Resource;

/**
 * Loads RSA keys from PEM files.
 *
 * <p>Only the two formats produced by ordinary {@code openssl} commands are understood:
 * {@code PRIVATE KEY} (PKCS#8) and {@code PUBLIC KEY} (X.509 SubjectPublicKeyInfo). The older
 * PKCS#1 header {@code RSA PRIVATE KEY} is rejected with an explanatory message rather than
 * failing obscurely, because it is a very common mistake.
 */
final class PemKeyLoader {

	private static final String PRIVATE_KEY_HEADER = "-----BEGIN PRIVATE KEY-----";

	private static final String PUBLIC_KEY_HEADER = "-----BEGIN PUBLIC KEY-----";

	private static final String PKCS1_PRIVATE_KEY_HEADER = "-----BEGIN RSA PRIVATE KEY-----";

	private PemKeyLoader() {
	}

	static RSAPrivateKey loadPrivateKey(Resource resource) {
		byte[] encoded = readPem(resource, PRIVATE_KEY_HEADER, PKCS1_PRIVATE_KEY_HEADER);
		try {
			return (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(encoded));
		}
		catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
			throw new IllegalStateException(
					"Unable to read an RSA private key from " + describe(resource) + ": " + ex.getMessage(), ex);
		}
	}

	static RSAPublicKey loadPublicKey(Resource resource) {
		byte[] encoded = readPem(resource, PUBLIC_KEY_HEADER, null);
		try {
			return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(encoded));
		}
		catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
			throw new IllegalStateException(
					"Unable to read an RSA public key from " + describe(resource) + ": " + ex.getMessage(), ex);
		}
	}

	/**
	 * Derive the matching public key from a private key.
	 *
	 * <p>Needed because the JWKS endpoint must publish a public key even when the deployment only
	 * configured a private key.
	 * @param privateKey the private key
	 * @return the corresponding public key
	 */
	static RSAPublicKey derivePublicKey(RSAPrivateKey privateKey) {
		if (!(privateKey instanceof RSAPrivateCrtKey crtKey)) {
			throw new IllegalStateException(
					"The configured RSA private key does not carry the modulus and public exponent, "
							+ "so the public key cannot be derived from it; configure app.security.jwt.public-key-location");
		}
		try {
			RSAPublicKeySpec spec = new RSAPublicKeySpec(crtKey.getModulus(), crtKey.getPublicExponent());
			return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(spec);
		}
		catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
			throw new IllegalStateException("Unable to derive the RSA public key: " + ex.getMessage(), ex);
		}
	}

	private static byte[] readPem(Resource resource, String expectedHeader, String rejectedHeader) {
		if (resource == null) {
			throw new IllegalStateException("No key resource was configured");
		}
		String pem;
		try (var input = resource.getInputStream()) {
			pem = new String(input.readAllBytes(), StandardCharsets.UTF_8);
		}
		catch (IOException ex) {
			throw new IllegalStateException("Unable to read the key from " + describe(resource), ex);
		}
		if (rejectedHeader != null && pem.contains(rejectedHeader)) {
			throw new IllegalStateException("The key at " + describe(resource) + " is in the legacy PKCS#1 format. "
					+ "Convert it to PKCS#8 first, for example: openssl pkcs8 -topk8 -nocrypt -in key.pem -out key-pkcs8.pem");
		}
		if (!pem.contains(expectedHeader)) {
			throw new IllegalStateException("The key at " + describe(resource) + " is not a PEM file starting with "
					+ expectedHeader + "; generate it with openssl.");
		}
		String base64 = pem.replaceAll("-----[A-Z ]+-----", "").replaceAll("\\s", "");
		try {
			return Base64.getDecoder().decode(base64);
		}
		catch (IllegalArgumentException ex) {
			throw new IllegalStateException("The key at " + describe(resource) + " is not valid Base64", ex);
		}
	}

	private static String describe(Resource resource) {
		return "'" + resource.getDescription() + "'";
	}

}
