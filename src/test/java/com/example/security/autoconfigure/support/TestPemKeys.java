package com.example.security.autoconfigure.support;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

/**
 * Generates RSA key material as PEM files so the key loading path is exercised for real rather than
 * mocked.
 */
public final class TestPemKeys {

	private TestPemKeys() {
	}

	public static RsaPair generate() {
		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
			generator.initialize(2048);
			KeyPair pair = generator.generateKeyPair();
			return new RsaPair((RSAPrivateKey) pair.getPrivate(), (RSAPublicKey) pair.getPublic());
		}
		catch (NoSuchAlgorithmException ex) {
			throw new IllegalStateException("RSA is not available", ex);
		}
	}

	public static String privateKeyPem(RSAPrivateKey key) {
		return pem("PRIVATE KEY", key.getEncoded());
	}

	public static String publicKeyPem(RSAPublicKey key) {
		return pem("PUBLIC KEY", key.getEncoded());
	}

	/**
	 * Produce a syntactically plausible PEM with a caller supplied header, used to test the
	 * diagnostics for formats this library does not accept.
	 * @param header the text between the BEGIN and END markers
	 * @return the PEM document
	 */
	public static String pem(String header, byte[] der) {
		String base64 = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(der);
		return "-----BEGIN " + header + "-----\n" + base64 + "\n-----END " + header + "-----\n";
	}

	public static Path write(Path directory, String fileName, String content) {
		try {
			Path file = directory.resolve(fileName);
			Files.writeString(file, content, StandardCharsets.UTF_8);
			return file;
		}
		catch (Exception ex) {
			throw new IllegalStateException("Unable to write " + fileName, ex);
		}
	}

	/**
	 * A matching RSA key pair.
	 *
	 * @param privateKey the private key
	 * @param publicKey the public key
	 */
	public record RsaPair(RSAPrivateKey privateKey, RSAPublicKey publicKey) {
	}

}
