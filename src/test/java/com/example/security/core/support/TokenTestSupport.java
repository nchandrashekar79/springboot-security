package com.example.security.core.support;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.example.security.core.token.JwtAlgorithm;
import com.example.security.core.token.TokenConfig;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.ImmutableSecret;

import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

import java.time.Duration;
import java.util.UUID;

/**
 * Builds encoder/decoder pairs and token configuration for tests.
 */
public final class TokenTestSupport {

	/**
	 * A secret long enough for HS256, which requires at least 256 bits.
	 */
	public static final String SECRET = "test-secret-value-that-is-long-enough-1234567890";

	private TokenTestSupport() {
	}

	public static SecretKey secretKey() {
		return secretKey(SECRET);
	}

	public static SecretKey secretKey(String value) {
		return new SecretKeySpec(value.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
	}

	public static JwtEncoder hs256Encoder() {
		return hs256Encoder(secretKey());
	}

	public static JwtEncoder hs256Encoder(SecretKey key) {
		return new NimbusJwtEncoder(new ImmutableSecret<>(key));
	}

	public static JwtDecoder hs256Decoder() {
		return hs256Decoder(secretKey());
	}

	public static JwtDecoder hs256Decoder(SecretKey key) {
		return NimbusJwtDecoder.withSecretKey(key).macAlgorithm(MacAlgorithm.HS256).build();
	}

	public static RSAKey rsaKey() {
		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
			generator.initialize(2048);
			KeyPair pair = generator.generateKeyPair();
			return new RSAKey.Builder((RSAPublicKey) pair.getPublic())
				.privateKey((RSAPrivateKey) pair.getPrivate())
				.keyID(UUID.randomUUID().toString())
				.build();
		}
		catch (NoSuchAlgorithmException ex) {
			throw new IllegalStateException("RSA is not available", ex);
		}
	}

	public static JwtEncoder rs256Encoder(RSAKey key) {
		return new NimbusJwtEncoder(new ImmutableJWKSet<>(new JWKSet(key)));
	}

	public static JwtDecoder rs256Decoder(RSAKey key) {
		try {
			return NimbusJwtDecoder.withPublicKey(key.toRSAPublicKey())
				.signatureAlgorithm(SignatureAlgorithm.RS256)
				.build();
		}
		catch (JOSEException ex) {
			throw new IllegalStateException("Unable to extract the RSA public key", ex);
		}
	}

	public static TokenConfig config(JwtAlgorithm algorithm) {
		return new TokenConfig("https://issuer.test", "test-audience", algorithm, "roles", Duration.ofMinutes(15),
				Duration.ofDays(7));
	}

}
