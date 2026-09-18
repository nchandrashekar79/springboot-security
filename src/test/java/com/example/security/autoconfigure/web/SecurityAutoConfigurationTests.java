package com.example.security.autoconfigure.web;

import com.example.security.autoconfigure.jwt.JwtAutoConfiguration;
import com.example.security.autoconfigure.jwt.TokenServiceAutoConfiguration;
import org.junit.jupiter.api.Test;

import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.security.web.SecurityFilterChain;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Covers the conditions under which the filter chain is installed. The behaviour of the chain
 * itself is exercised against a real application context in {@code StarterConsumerTests}, because
 * that is where a genuine Boot auto-configured {@code HttpSecurity} exists.
 */
class SecurityAutoConfigurationTests {

	private static final String SECRET = "a-secret-that-is-definitely-long-enough-1234567890";

	private final ApplicationContextRunner runner = new ApplicationContextRunner()
		.withConfiguration(AutoConfigurations.of(JwtAutoConfiguration.class, TokenServiceAutoConfiguration.class,
				SecurityAutoConfiguration.class))
		.withPropertyValues("app.security.jwt.secret=" + SECRET);

	@Test
	void doesNotInstallAChainInANonWebApplication() {
		this.runner.run((context) -> {
			assertThat(context).doesNotHaveBean(SecurityFilterChain.class);
			assertThat(context).doesNotHaveBean(JsonAuthenticationEntryPoint.class);
			// The token machinery is still available for applications that only issue or verify.
			assertThat(context).hasBean("tokenVerifier");
		});
	}

	@Test
	void doesNotInstallAnythingWhenDisabled() {
		this.runner.withPropertyValues("app.security.enabled=false").run((context) -> {
			assertThat(context).doesNotHaveBean(SecurityFilterChain.class);
			assertThat(context).doesNotHaveBean(JsonAuthenticationEntryPoint.class);
			assertThat(context).doesNotHaveBean(JsonAccessDeniedHandler.class);
		});
	}

}
