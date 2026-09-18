package com.example.security.autoconfigure;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;

/**
 * Extension point for adding authorization rules, such as "only administrators may call
 * {@code /admin/**}".
 *
 * <p>This exists separately from {@link JwtSecurityCustomizer} because of evaluation order.
 * Authorization rules are matched in registration order and the first match wins, and the library
 * always registers a catch-all rule last. A rule added through {@link JwtSecurityCustomizer} would
 * therefore sit <em>after</em> the catch-all and never be reached. Rules added here are registered
 * before it, so they take effect.
 *
 * <p>Example:
 * <pre>{@code
 * @Bean
 * JwtAuthorizationCustomizer adminOnly() {
 * 	return (registry) -> registry.requestMatchers("/admin/**").hasRole("ADMIN");
 * }
 * }</pre>
 */
@FunctionalInterface
public interface JwtAuthorizationCustomizer {

	/**
	 * Register additional rules. Rules added by one customizer are visible to the next, and all of
	 * them run before the library's catch-all.
	 * @param registry the registry to add matchers to
	 */
	void customize(AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry registry);

}
