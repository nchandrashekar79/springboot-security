package com.example.security.autoconfigure;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;

/**
 * Extension point for tuning the filter chain the library installs.
 *
 * <p>Implementations are applied in {@code @Order} sequence after the library has finished
 * configuring the chain, so a customizer can refine the library's decisions without having to
 * redefine the whole chain. This is the recommended alternative to declaring a
 * {@code SecurityFilterChain} bean, which would switch the library's chain off entirely.
 */
@FunctionalInterface
public interface JwtSecurityCustomizer {

	/**
	 * Customize the chain.
	 * @param http the chain under construction
	 * @throws Exception if customization fails
	 */
	void customize(HttpSecurity http) throws Exception;

}
