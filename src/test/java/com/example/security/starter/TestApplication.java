package com.example.security.starter;

import com.example.security.autoconfigure.JwtAuthorizationCustomizer;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * A stand-in for a real consuming web application.
 *
 * <p>It is deliberately not annotated with anything from this library beyond the public extension
 * point below, so the security behaviour it exhibits comes from the auto-configuration alone and
 * not from explicit wiring in the test.
 *
 * <p>One limitation is worth being explicit about, because it is a consequence of the library
 * being a single module: these tests run on this module's own classpath, so they prove that the
 * auto-configuration works over real HTTP, but they cannot prove that the published jar's
 * dependency metadata is complete. The web starter it needs is declared test scoped here, whereas
 * a consuming application declares it itself.
 */
@SpringBootApplication
@EnableMethodSecurity
@RestController
public class TestApplication {

	public static void main(String[] args) {
		SpringApplication.run(TestApplication.class, args);
	}

	@GetMapping("/open")
	String open() {
		return "open";
	}

	@GetMapping("/protected")
	String protectedEndpoint() {
		return "protected";
	}

	@GetMapping("/staff")
	String staff() {
		return "staff";
	}

	@GetMapping("/admin")
	@PreAuthorize("hasRole('ADMIN')")
	String admin() {
		return "admin";
	}

	/**
	 * Demonstrates adding a path rule without replacing the library's chain.
	 * @return the customizer
	 */
	@Bean
	JwtAuthorizationCustomizer staffOnly() {
		return (registry) -> registry.requestMatchers("/staff").hasRole("STAFF");
	}

}
