package com.example.security.autoconfigure.jwt;

import com.example.security.autoconfigure.revocation.RemoteIntrospectionRevocationStore;
import com.example.security.core.revocation.InMemoryRevocationStore;
import com.example.security.core.revocation.RevocationRegistry;
import com.example.security.core.revocation.RevocationStore;
import org.junit.jupiter.api.Test;

import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

class TokenServiceAutoConfigurationTests {

	private static final String SECRET = "a-secret-that-is-definitely-long-enough-1234567890";

	private final ApplicationContextRunner runner = new ApplicationContextRunner()
		.withConfiguration(AutoConfigurations.of(JwtAutoConfiguration.class, TokenServiceAutoConfiguration.class))
		.withPropertyValues("app.security.jwt.secret=" + SECRET);

	@Test
	void disablesRevocationByDefault() {
		this.runner.run((context) -> assertThat(context).doesNotHaveBean(RevocationStore.class));
	}

	@Test
	void localRevocationProducesAStoreThatCanAlsoRevoke() {
		this.runner.withPropertyValues("app.security.revocation.enabled=true").run((context) -> {
			assertThat(context).hasSingleBean(InMemoryRevocationStore.class);
			assertThat(context).hasSingleBean(RevocationRegistry.class);
			RevocationStore store = context.getBean(RevocationStore.class);
			assertThat(store.isRevoked("unknown")).isFalse();
		});
	}

	@Test
	void localRevocationIsNotCreatedWhenRevocationIsDisabled() {
		this.runner.withPropertyValues("app.security.revocation.mode=LOCAL").run((context) -> {
			assertThat(context).doesNotHaveBean(RevocationRegistry.class);
		});
	}

	@Test
	void remoteRevocationProducesAReadOnlyStore() {
		this.runner
			.withPropertyValues("app.security.revocation.enabled=true", "app.security.revocation.mode=REMOTE",
					"app.security.revocation.introspection-uri=http://localhost:9000/auth/introspect",
					"app.security.revocation.introspection-secret=s3cret")
			.run((context) -> {
				assertThat(context).hasSingleBean(RemoteIntrospectionRevocationStore.class);
				assertThat(context).hasSingleBean(RevocationStore.class);
				// A consumer must not be able to become a second source of revocation truth.
				assertThat(context).doesNotHaveBean(RevocationRegistry.class);
				assertThat(context).doesNotHaveBean(InMemoryRevocationStore.class);
			});
	}

	@Test
	void remoteRevocationRequiresAnIntrospectionUri() {
		this.runner.withPropertyValues("app.security.revocation.enabled=true",
				"app.security.revocation.mode=REMOTE")
			.run((context) -> {
				assertThat(context).hasFailed();
				assertThat(context.getStartupFailure()).getRootCause()
					.hasMessageContaining("introspectionUri must not be blank");
			});
	}

}
