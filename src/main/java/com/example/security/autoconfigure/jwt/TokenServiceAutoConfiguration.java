package com.example.security.autoconfigure.jwt;

import com.example.security.autoconfigure.AppSecurityProperties;
import com.example.security.autoconfigure.RevocationMode;
import com.example.security.autoconfigure.revocation.RemoteIntrospectionRevocationStore;
import com.example.security.core.revocation.InMemoryRevocationStore;
import com.example.security.core.revocation.RevocationRegistry;
import com.example.security.core.revocation.RevocationStore;
import com.example.security.core.token.TokenConfig;
import com.example.security.core.token.TokenService;
import com.example.security.core.token.TokenVerifier;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.web.client.RestClient;

/**
 * Exposes the token service objects an application needs, once the key material exists.
 *
 * <p>Ordered after {@link JwtAutoConfiguration} on purpose: the {@link ConditionalOnBean}
 * conditions here are only reliable if the encoder and decoder bean definitions have already been
 * registered, and the {@code after} attribute on {@code @AutoConfiguration} is what guarantees
 * that. Relying on declaration order within a single configuration class would not.
 */
@AutoConfiguration(after = JwtAutoConfiguration.class)
@ConditionalOnProperty(prefix = "app.security", name = "enabled", havingValue = "true", matchIfMissing = true)
public class TokenServiceAutoConfiguration {

	/**
	 * Only present for applications that hold a signing key. A consumer verifying with a public key
	 * has no encoder, so it cannot mint tokens, which is the intended asymmetry.
	 */
	@Bean
	@ConditionalOnMissingBean
	@ConditionalOnBean(JwtEncoder.class)
	TokenService tokenService(JwtEncoder jwtEncoder, TokenConfig tokenConfig) {
		return new TokenService(jwtEncoder, tokenConfig);
	}

	@Bean
	@ConditionalOnMissingBean
	@ConditionalOnBean(JwtDecoder.class)
	TokenVerifier tokenVerifier(JwtDecoder jwtDecoder) {
		return new TokenVerifier(jwtDecoder);
	}

	/**
	 * In-memory revocation. Correct only when this process is also the issuer.
	 */
	@Configuration(proxyBeanMethods = false)
	@ConditionalOnProperty(prefix = "app.security.revocation", name = "mode", havingValue = "LOCAL", matchIfMissing = true)
	static class LocalRevocationConfiguration {

		@Bean
		@ConditionalOnMissingBean(RevocationRegistry.class)
		@ConditionalOnProperty(prefix = "app.security.revocation", name = "enabled", havingValue = "true")
		InMemoryRevocationStore inMemoryRevocationStore() {
			return new InMemoryRevocationStore();
		}

	}

	/**
	 * Remote revocation. Mutually exclusive with the local configuration at class level, so the two
	 * bean definitions can never race each other.
	 */
	@Configuration(proxyBeanMethods = false)
	@ConditionalOnProperty(prefix = "app.security.revocation", name = "mode", havingValue = "REMOTE")
	static class RemoteRevocationConfiguration {

		@Bean
		@ConditionalOnMissingBean(RevocationStore.class)
		@ConditionalOnProperty(prefix = "app.security.revocation", name = "enabled", havingValue = "true")
		RemoteIntrospectionRevocationStore remoteIntrospectionRevocationStore(AppSecurityProperties properties,
				ObjectProvider<RestClient.Builder> restClientBuilder) {
			AppSecurityProperties.Revocation revocation = properties.getRevocation();
			RestClient.Builder builder = restClientBuilder.getIfAvailable(RestClient::builder);
			return new RemoteIntrospectionRevocationStore(builder.build(), revocation.getIntrospectionUri(),
					revocation.getIntrospectionSecret(), revocation.getCacheTtl());
		}

	}

	/**
	 * Exposed so that configuration errors point at the setting rather than at a missing bean.
	 * @return the configured revocation mode
	 */
	@Bean
	@ConditionalOnMissingBean
	RevocationMode revocationMode(AppSecurityProperties properties) {
		return properties.getRevocation().getMode();
	}

}
