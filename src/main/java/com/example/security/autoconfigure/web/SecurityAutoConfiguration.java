package com.example.security.autoconfigure.web;

import java.util.List;

import com.example.security.autoconfigure.AppSecurityProperties;
import com.example.security.autoconfigure.JwtAuthorizationCustomizer;
import com.example.security.autoconfigure.JwtSecurityCustomizer;
import com.example.security.autoconfigure.jwt.JwtAutoConfiguration;
import com.example.security.core.revocation.RevocationStore;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;

/**
 * Installs a stateless bearer-token filter chain.
 *
 * <p>Every bean here is {@link ConditionalOnMissingBean conditional} and the chain itself is
 * guarded on {@code SecurityFilterChain}, so an application that declares its own chain wins and
 * this configuration contributes nothing. Applications that only want to adjust the rules should
 * register a {@link JwtSecurityCustomizer} instead, which leaves the reasoning below intact.
 */
@AutoConfiguration(after = JwtAutoConfiguration.class)
@ConditionalOnClass({ JwtDecoder.class, BearerTokenAuthenticationFilter.class })
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnProperty(prefix = "app.security", name = "enabled", havingValue = "true", matchIfMissing = true)
public class SecurityAutoConfiguration {

	/**
	 * Maps the configured authorities claim onto Spring Security authorities.
	 */
	@Bean
	@ConditionalOnMissingBean
	JwtAuthenticationConverter jwtAuthenticationConverter(AppSecurityProperties properties) {
		JwtGrantedAuthoritiesConverter authorities = new JwtGrantedAuthoritiesConverter();
		authorities.setAuthoritiesClaimName(properties.getJwt().getAuthoritiesClaim());
		authorities.setAuthorityPrefix(properties.getJwt().getAuthorityPrefix());
		JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
		converter.setJwtGrantedAuthoritiesConverter(authorities);
		return converter;
	}

	@Bean
	@ConditionalOnMissingBean(AuthenticationEntryPoint.class)
	JsonAuthenticationEntryPoint jsonAuthenticationEntryPoint() {
		return new JsonAuthenticationEntryPoint();
	}

	@Bean
	@ConditionalOnMissingBean(AccessDeniedHandler.class)
	JsonAccessDeniedHandler jsonAccessDeniedHandler() {
		return new JsonAccessDeniedHandler();
	}

	@Bean
	@ConditionalOnMissingBean(SecurityFilterChain.class)
	SecurityFilterChain appSecurityFilterChain(HttpSecurity http, AppSecurityProperties properties,
			JwtAuthenticationConverter jwtAuthenticationConverter, JsonAuthenticationEntryPoint entryPoint,
			JsonAccessDeniedHandler accessDeniedHandler, ObjectProvider<RevocationStore> revocationStores,
			ObjectProvider<JwtAuthorizationCustomizer> authorizationCustomizers,
			ObjectProvider<JwtSecurityCustomizer> customizers) throws Exception {
		List<String> permitPaths = properties.getPermitPaths();
		http
			// No cookies are issued, so there is no cross-site request forgery surface to protect.
			.csrf(AbstractHttpConfigurer::disable)
			// Each request must carry its own token; nothing is remembered between requests.
			.sessionManagement((session) -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
			.authorizeHttpRequests((authorize) -> {
				if (permitPaths != null && !permitPaths.isEmpty()) {
					authorize.requestMatchers(permitPaths.toArray(String[]::new)).permitAll();
				}
				// Rules contributed by the application are registered here so that they are still
				// matched before the catch-all below; anything registered after it would be dead.
				authorizationCustomizers.orderedStream()
					.forEach((customizer) -> applyAuthorization(customizer, authorize));
				authorize.anyRequest().authenticated();
			})
			.exceptionHandling((exceptions) -> exceptions.authenticationEntryPoint(entryPoint)
				.accessDeniedHandler(accessDeniedHandler))
			.oauth2ResourceServer(
					(oauth2) -> oauth2.jwt((jwt) -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter)));

		RevocationStore revocationStore = revocationStores.getIfAvailable();
		// Installed unconditionally: even with revocation switched off, a refresh token must not be
		// usable as a bearer credential.
		http.addFilterAfter(
				new JwtBearerTokenValidationFilter(entryPoint, properties.getJwt().isRequireAccessTokenType(),
						revocationStore),
				BearerTokenAuthenticationFilter.class);

		customizers.orderedStream().forEach((customizer) -> apply(customizer, http));
		return http.build();
	}

	private static void applyAuthorization(JwtAuthorizationCustomizer customizer,
			AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry registry) {
		try {
			customizer.customize(registry);
		}
		catch (Exception ex) {
			throw new IllegalStateException(
					"A " + customizer.getClass().getName() + " failed to add authorization rules", ex);
		}
	}

	private static void apply(JwtSecurityCustomizer customizer, HttpSecurity http) {
		try {
			customizer.customize(http);
		}
		catch (Exception ex) {
			throw new IllegalStateException("A " + customizer.getClass().getName() + " failed to customize the chain",
					ex);
		}
	}

}
