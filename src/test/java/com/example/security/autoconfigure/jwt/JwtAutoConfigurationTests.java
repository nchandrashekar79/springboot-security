package com.example.security.autoconfigure.jwt;

import java.nio.file.Path;

import com.example.security.autoconfigure.AppSecurityProperties;
import com.example.security.autoconfigure.support.TestPemKeys;
import com.example.security.core.token.JwtAlgorithm;
import com.example.security.core.token.TokenConfig;
import com.example.security.core.token.TokenService;
import com.example.security.core.token.TokenVerifier;
import com.nimbusds.jose.jwk.JWKSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;

import static org.assertj.core.api.Assertions.assertThat;

class JwtAutoConfigurationTests {

	private static final String SECRET = "a-secret-that-is-definitely-long-enough-1234567890";

	private final ApplicationContextRunner runner = new ApplicationContextRunner()
		.withConfiguration(AutoConfigurations.of(JwtAutoConfiguration.class, TokenServiceAutoConfiguration.class));

	@Test
	void createsDecoderEncoderAndTokenServicesForHs256() {
		this.runner.withPropertyValues("app.security.jwt.secret=" + SECRET).run((context) -> {
			assertThat(context).hasSingleBean(JwtDecoder.class);
			assertThat(context).hasSingleBean(JwtEncoder.class);
			assertThat(context).hasSingleBean(TokenConfig.class);
			assertThat(context).hasSingleBean(TokenService.class);
			assertThat(context).hasSingleBean(TokenVerifier.class);
		});
	}

	@Test
	void mapsPropertiesOntoTheTokenShape() {
		this.runner
			.withPropertyValues("app.security.jwt.secret=" + SECRET, "app.security.jwt.issuer=https://issuer.test",
					"app.security.jwt.audience=my-audience", "app.security.jwt.authorities-claim=permissions",
					"app.security.jwt.access-token-ttl=5m", "app.security.jwt.refresh-token-ttl=1d")
			.run((context) -> {
				TokenConfig config = context.getBean(TokenConfig.class);
				assertThat(config.issuer()).isEqualTo("https://issuer.test");
				assertThat(config.audience()).isEqualTo("my-audience");
				assertThat(config.authoritiesClaim()).isEqualTo("permissions");
				assertThat(config.accessTokenTtl()).hasMinutes(5);
				assertThat(config.refreshTokenTtl()).hasDays(1);
			});
	}

	@Test
	void failsLoudlyWhenTheHs256SecretIsTooShort() {
		this.runner.withPropertyValues("app.security.jwt.secret=too-short").run((context) -> {
			assertThat(context).hasFailed();
			assertThat(context.getStartupFailure()).getRootCause()
				.hasMessageContaining("app.security.jwt.secret must be at least 32 bytes");
		});
	}

	@Test
	void failsLoudlyWhenNoSecretIsConfiguredAtAll() {
		this.runner.run((context) -> {
			assertThat(context).hasFailed();
			assertThat(context.getStartupFailure()).getRootCause()
				.hasMessageContaining("app.security.jwt.secret must be at least 32 bytes");
		});
	}

	@Test
	void backsOffEntirelyWhenDisabled() {
		this.runner.withPropertyValues("app.security.enabled=false", "app.security.jwt.secret=" + SECRET)
			.run((context) -> {
				assertThat(context).doesNotHaveBean(JwtDecoder.class);
				assertThat(context).doesNotHaveBean(JwtEncoder.class);
				assertThat(context).doesNotHaveBean(TokenConfig.class);
				assertThat(context).doesNotHaveBean(AppSecurityProperties.class);
			});
	}

	@Test
	void yieldsToAnApplicationSuppliedDecoder() {
		this.runner.withPropertyValues("app.security.jwt.secret=" + SECRET)
			.withUserConfiguration(CustomDecoderConfiguration.class)
			.run((context) -> assertThat(context.getBean(JwtDecoder.class))
				.isSameAs(CustomDecoderConfiguration.DECODER));
	}

	@Test
	void createsDecoderEncoderAndJwksFromAPkcs8PrivateKey(@TempDir Path tempDir) {
		TestPemKeys.RsaPair pair = TestPemKeys.generate();
		Path privateKey = TestPemKeys.write(tempDir, "private.pem", TestPemKeys.privateKeyPem(pair.privateKey()));

		this.runner.withPropertyValues("app.security.jwt.algorithm=RS256",
				"app.security.jwt.private-key-location=" + privateKey.toUri(), "app.security.jwt.key-id=test-key")
			.run((context) -> {
				assertThat(context).hasSingleBean(JwtDecoder.class);
				assertThat(context).hasSingleBean(JwtEncoder.class);
				assertThat(context).hasSingleBean(JWKSet.class);
				assertThat(context.getBean(JWKSet.class).getKeys()).singleElement().satisfies((key) -> {
					assertThat(key.getKeyID()).isEqualTo("test-key");
					// The JWKS endpoint must publish a public key only; the private half stays behind.
					assertThat(key.isPrivate()).isTrue();
				});
			});
	}

	@Test
	void aVerifyingConsumerGetsNoEncoderBecauseItHoldsNoPrivateKey(@TempDir Path tempDir) {
		TestPemKeys.RsaPair pair = TestPemKeys.generate();
		Path publicKey = TestPemKeys.write(tempDir, "public.pem", TestPemKeys.publicKeyPem(pair.publicKey()));

		this.runner.withPropertyValues("app.security.jwt.algorithm=RS256",
				"app.security.jwt.public-key-location=" + publicKey.toUri())
			.run((context) -> {
				assertThat(context).hasSingleBean(JwtDecoder.class);
				assertThat(context).doesNotHaveBean(JwtEncoder.class);
				assertThat(context).doesNotHaveBean(JWKSet.class);
				// Without an encoder there is nothing to issue with, which is the point.
				assertThat(context).doesNotHaveBean(TokenService.class);
				assertThat(context).hasSingleBean(TokenVerifier.class);
			});
	}

	@Test
	void failsLoudlyWhenRs256HasNoKeyMaterialAtAll() {
		this.runner.withPropertyValues("app.security.jwt.algorithm=RS256").run((context) -> {
			assertThat(context).hasFailed();
			assertThat(context.getStartupFailure()).getRootCause()
				.hasMessageContaining("RS256 verification needs one of app.security.jwt.jwk-set-uri");
		});
	}

	@Test
	void explainsHowToConvertALegacyPkcs1PrivateKey(@TempDir Path tempDir) {
		TestPemKeys.RsaPair pair = TestPemKeys.generate();
		Path pkcs1 = TestPemKeys.write(tempDir, "legacy.pem",
				TestPemKeys.pem("RSA PRIVATE KEY", pair.privateKey().getEncoded()));

		this.runner.withPropertyValues("app.security.jwt.algorithm=RS256",
				"app.security.jwt.private-key-location=" + pkcs1.toUri())
			.run((context) -> {
				assertThat(context).hasFailed();
				assertThat(context.getStartupFailure()).getRootCause()
					.hasMessageContaining("legacy PKCS#1 format")
					.hasMessageContaining("openssl pkcs8");
			});
	}

	@Test
	void rejectsAFileThatIsNotAPemKeyAtAll(@TempDir Path tempDir) {
		Path notAKey = TestPemKeys.write(tempDir, "notes.txt", "this is not a key");

		this.runner.withPropertyValues("app.security.jwt.algorithm=RS256",
				"app.security.jwt.private-key-location=" + notAKey.toUri())
			.run((context) -> {
				assertThat(context).hasFailed();
				assertThat(context.getStartupFailure()).getRootCause()
					.hasMessageContaining("is not a PEM file starting with");
			});
	}

	@Test
	void theAlgorithmDefaultsToHs256() {
		this.runner.withPropertyValues("app.security.jwt.secret=" + SECRET)
			.run((context) -> assertThat(context.getBean(TokenConfig.class).algorithm())
				.isEqualTo(JwtAlgorithm.HS256));
	}

	@Configuration(proxyBeanMethods = false)
	static class CustomDecoderConfiguration {

		static final JwtDecoder DECODER = (token) -> {
			throw new UnsupportedOperationException("only here to prove the library backs off");
		};

		@Bean
		JwtDecoder customJwtDecoder() {
			return DECODER;
		}

	}

}
