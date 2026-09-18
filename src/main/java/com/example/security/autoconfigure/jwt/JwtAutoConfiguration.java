package com.example.security.autoconfigure.jwt;

import java.nio.charset.StandardCharsets;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.example.security.autoconfigure.AppSecurityProperties;
import com.example.security.core.token.TokenConfig;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.ImmutableSecret;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

/**
 * Turns {@code app.security.jwt.*} into the encoder, decoder and token shape everything else uses.
 *
 * <p>Both the encoder and the decoder are {@link ConditionalOnMissingBean conditional}, so an
 * application that already builds its own can simply declare it and this configuration steps
 * aside. A consumer that only verifies tokens never receives an encoder, because it has no private
 * key: that asymmetry is intentional and is what makes RS256 deployments safe.
 */
@AutoConfiguration
@ConditionalOnProperty(prefix = "app.security", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties(AppSecurityProperties.class)
public class JwtAutoConfiguration {

	/**
	 * HS256 accepts a 256 bit key at minimum, so a shorter secret is a configuration error worth
	 * failing loudly on rather than silently padding.
	 */
	private static final int MINIMUM_HS256_SECRET_BYTES = 32;

	@Bean
	@ConditionalOnMissingBean
	TokenConfig tokenConfig(AppSecurityProperties properties) {
		AppSecurityProperties.Jwt jwt = properties.getJwt();
		return new TokenConfig(jwt.getIssuer(), jwt.getAudience(), jwt.getAlgorithm(), jwt.getAuthoritiesClaim(),
				jwt.getAccessTokenTtl(), jwt.getRefreshTokenTtl());
	}

	/**
	 * Symmetric configuration: the same secret signs and verifies, so every application that
	 * verifies a token can also forge one. Suitable for local development.
	 */
	@Configuration(proxyBeanMethods = false)
	@ConditionalOnProperty(prefix = "app.security.jwt", name = "algorithm", havingValue = "HS256", matchIfMissing = true)
	static class Hs256Configuration {

		@Bean
		@ConditionalOnMissingBean
		SecretKey jwtSecretKey(AppSecurityProperties properties) {
			String secret = properties.getJwt().getSecret();
			byte[] bytes = (secret != null) ? secret.getBytes(StandardCharsets.UTF_8) : new byte[0];
			if (bytes.length < MINIMUM_HS256_SECRET_BYTES) {
				String message = "app.security.jwt.secret must be at least %d bytes for HS256 but %d were supplied. "
						+ "Set a longer secret, or switch to app.security.jwt.algorithm=RS256 so that "
						+ "consumers only need a public key.";
				throw new IllegalStateException(message.formatted(MINIMUM_HS256_SECRET_BYTES, bytes.length));
			}
			return new SecretKeySpec(bytes, properties.getJwt().getAlgorithm().keyAlgorithm());
		}

		@Bean
		@ConditionalOnMissingBean
		JwtDecoder jwtDecoder(SecretKey jwtSecretKey, AppSecurityProperties properties) {
			NimbusJwtDecoder decoder = NimbusJwtDecoder.withSecretKey(jwtSecretKey)
				.macAlgorithm(MacAlgorithm.HS256)
				.build();
			decoder.setJwtValidator(TokenValidators.from(properties));
			return decoder;
		}

		@Bean
		@ConditionalOnMissingBean
		JwtEncoder jwtEncoder(SecretKey jwtSecretKey) {
			return new NimbusJwtEncoder(new ImmutableSecret<>(jwtSecretKey));
		}

	}

	/**
	 * Asymmetric configuration: verification needs only a public key, which is why this is the
	 * recommended shape once the issuer and the consumers are deployed separately.
	 */
	@Configuration(proxyBeanMethods = false)
	@ConditionalOnProperty(prefix = "app.security.jwt", name = "algorithm", havingValue = "RS256")
	static class Rs256Configuration {

		@Bean
		@ConditionalOnMissingBean
		JwtDecoder jwtDecoder(AppSecurityProperties properties) {
			AppSecurityProperties.Jwt jwt = properties.getJwt();
			NimbusJwtDecoder decoder;
			if (jwt.getJwkSetUri() != null) {
				decoder = NimbusJwtDecoder.withJwkSetUri(jwt.getJwkSetUri()).build();
			}
			else {
				RSAPublicKey publicKey = resolvePublicKey(jwt);
				decoder = NimbusJwtDecoder.withPublicKey(publicKey)
					.signatureAlgorithm(SignatureAlgorithm.RS256)
					.build();
			}
			decoder.setJwtValidator(TokenValidators.from(properties));
			return decoder;
		}

		private static RSAPublicKey resolvePublicKey(AppSecurityProperties.Jwt jwt) {
			if (jwt.getPublicKeyLocation() != null) {
				return PemKeyLoader.loadPublicKey(jwt.getPublicKeyLocation());
			}
			if (jwt.getPrivateKeyLocation() != null) {
				return PemKeyLoader.derivePublicKey(PemKeyLoader.loadPrivateKey(jwt.getPrivateKeyLocation()));
			}
			throw new IllegalStateException("RS256 verification needs one of app.security.jwt.jwk-set-uri, "
					+ "app.security.jwt.public-key-location or app.security.jwt.private-key-location");
		}

		/**
		 * Signing is nested one level deeper because only the issuer has a private key. An
		 * application that merely verifies therefore gets no encoder at all.
		 */
		@Configuration(proxyBeanMethods = false)
		@ConditionalOnProperty(prefix = "app.security.jwt", name = "private-key-location")
		static class SigningConfiguration {

			@Bean
			@ConditionalOnMissingBean
			JWKSet jwtKeySet(AppSecurityProperties properties) {
				AppSecurityProperties.Jwt jwt = properties.getJwt();
				RSAPrivateKey privateKey = PemKeyLoader.loadPrivateKey(jwt.getPrivateKeyLocation());
				RSAPublicKey publicKey = (jwt.getPublicKeyLocation() != null)
						? PemKeyLoader.loadPublicKey(jwt.getPublicKeyLocation())
						: PemKeyLoader.derivePublicKey(privateKey);
				RSAKey rsaKey = new RSAKey.Builder(publicKey).privateKey(privateKey).keyID(jwt.getKeyId()).build();
				return new JWKSet(rsaKey);
			}

			@Bean
			@ConditionalOnMissingBean
			JwtEncoder jwtEncoder(JWKSet jwtKeySet) {
				return new NimbusJwtEncoder(new ImmutableJWKSet<>(jwtKeySet));
			}

		}

	}

}
