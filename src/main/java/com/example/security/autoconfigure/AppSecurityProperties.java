package com.example.security.autoconfigure;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import com.example.security.core.token.JwtAlgorithm;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.io.Resource;

/**
 * Configuration for the shared JWT security library.
 *
 * <p>Deliberately namespaced under {@code app.security} rather than {@code spring.security},
 * because Spring Boot reserves the {@code spring}, {@code server} and {@code management}
 * namespaces for its own use.
 */
@ConfigurationProperties(prefix = "app.security")
public class AppSecurityProperties {

	/**
	 * Whether the shared security auto-configuration is active.
	 */
	private boolean enabled = true;

	/**
	 * Comma-separated list of request patterns reachable without a token, for example
	 * /actuator/health/**.
	 */
	private List<String> permitPaths = new ArrayList<>(List.of("/actuator/health/**"));

	private final Jwt jwt = new Jwt();

	private final Revocation revocation = new Revocation();

	public boolean isEnabled() {
		return this.enabled;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	public List<String> getPermitPaths() {
		return this.permitPaths;
	}

	public void setPermitPaths(List<String> permitPaths) {
		this.permitPaths = permitPaths;
	}

	public Jwt getJwt() {
		return this.jwt;
	}

	public Revocation getRevocation() {
		return this.revocation;
	}

	/**
	 * Token and key material settings.
	 */
	public static class Jwt {

		/**
		 * Value written to the iss claim and required of every accepted token.
		 */
		private String issuer = "springboot-security";

		/**
		 * Value written to the aud claim and required of every accepted token.
		 */
		private String audience = "springboot-security-clients";

		/**
		 * Signing algorithm. HS256 uses a shared secret; RS256 uses an RSA key pair and lets
		 * consumers verify with a public key alone.
		 */
		private JwtAlgorithm algorithm = JwtAlgorithm.HS256;

		/**
		 * Shared secret used to sign and verify tokens when the algorithm is HS256. Must be at
		 * least 32 bytes, which is the minimum HS256 accepts.
		 */
		private String secret;

		/**
		 * Key identifier published as the kid header and in the JWKS document.
		 */
		private String keyId = "springboot-security";

		/**
		 * PEM encoded PKCS#8 private key used to sign tokens when the algorithm is RS256. Only the
		 * token issuer needs this.
		 */
		private Resource privateKeyLocation;

		/**
		 * PEM encoded X.509 public key used to verify tokens when the algorithm is RS256. When
		 * omitted, the public key is derived from the private key.
		 */
		private Resource publicKeyLocation;

		/**
		 * JWKS endpoint used to verify RS256 tokens. Takes precedence over
		 * public-key-location.
		 */
		private String jwkSetUri;

		/**
		 * Lifetime of an access token. Keep this short, because an access token cannot be
		 * withdrawn from a consumer that does not share the revocation store.
		 */
		private Duration accessTokenTtl = Duration.ofMinutes(15);

		/**
		 * Lifetime of a refresh token.
		 */
		private Duration refreshTokenTtl = Duration.ofDays(7);

		/**
		 * Tolerance applied when checking the exp and nbf claims, to absorb clock drift between
		 * the issuer and the consumer.
		 */
		private Duration clockSkew = Duration.ofSeconds(60);

		/**
		 * Claim that carries the caller's authorities.
		 */
		private String authoritiesClaim = "roles";

		/**
		 * Prefix added to each authority found in the authorities claim. Empty by default, because
		 * the issuer writes authority strings verbatim: adding a prefix here would turn ROLE_STAFF
		 * into ROLE_ROLE_STAFF and every hasRole check would fail. Set this only when accepting
		 * tokens from an issuer that puts bare role names in the claim.
		 */
		private String authorityPrefix = "";

		/**
		 * Whether an accepted token must declare itself an access token. Leave this enabled when the
		 * tokens are issued by this library, otherwise a refresh token can be used as a bearer
		 * credential. Disable it only when accepting tokens from a third party that does not set the
		 * token_type claim.
		 */
		private boolean requireAccessTokenType = true;

		public String getIssuer() {
			return this.issuer;
		}

		public void setIssuer(String issuer) {
			this.issuer = issuer;
		}

		public String getAudience() {
			return this.audience;
		}

		public void setAudience(String audience) {
			this.audience = audience;
		}

		public JwtAlgorithm getAlgorithm() {
			return this.algorithm;
		}

		public void setAlgorithm(JwtAlgorithm algorithm) {
			this.algorithm = algorithm;
		}

		public String getSecret() {
			return this.secret;
		}

		public void setSecret(String secret) {
			this.secret = secret;
		}

		public String getKeyId() {
			return this.keyId;
		}

		public void setKeyId(String keyId) {
			this.keyId = keyId;
		}

		public Resource getPrivateKeyLocation() {
			return this.privateKeyLocation;
		}

		public void setPrivateKeyLocation(Resource privateKeyLocation) {
			this.privateKeyLocation = privateKeyLocation;
		}

		public Resource getPublicKeyLocation() {
			return this.publicKeyLocation;
		}

		public void setPublicKeyLocation(Resource publicKeyLocation) {
			this.publicKeyLocation = publicKeyLocation;
		}

		public String getJwkSetUri() {
			return this.jwkSetUri;
		}

		public void setJwkSetUri(String jwkSetUri) {
			this.jwkSetUri = jwkSetUri;
		}

		public Duration getAccessTokenTtl() {
			return this.accessTokenTtl;
		}

		public void setAccessTokenTtl(Duration accessTokenTtl) {
			this.accessTokenTtl = accessTokenTtl;
		}

		public Duration getRefreshTokenTtl() {
			return this.refreshTokenTtl;
		}

		public void setRefreshTokenTtl(Duration refreshTokenTtl) {
			this.refreshTokenTtl = refreshTokenTtl;
		}

		public Duration getClockSkew() {
			return this.clockSkew;
		}

		public void setClockSkew(Duration clockSkew) {
			this.clockSkew = clockSkew;
		}

		public String getAuthoritiesClaim() {
			return this.authoritiesClaim;
		}

		public void setAuthoritiesClaim(String authoritiesClaim) {
			this.authoritiesClaim = authoritiesClaim;
		}

		public String getAuthorityPrefix() {
			return this.authorityPrefix;
		}

		public void setAuthorityPrefix(String authorityPrefix) {
			this.authorityPrefix = authorityPrefix;
		}

		public boolean isRequireAccessTokenType() {
			return this.requireAccessTokenType;
		}

		public void setRequireAccessTokenType(boolean requireAccessTokenType) {
			this.requireAccessTokenType = requireAccessTokenType;
		}

	}

	/**
	 * Revocation settings. Disabled by default, because enabling it without a shared store gives a
	 * false sense of protection.
	 */
	public static class Revocation {

		/**
		 * Whether revoked tokens are rejected.
		 */
		private boolean enabled = false;

		/**
		 * Where revocation decisions come from. LOCAL keeps them in this JVM, which only works when
		 * a single process issues and consumes the tokens; REMOTE asks the token issuer.
		 */
		private RevocationMode mode = RevocationMode.LOCAL;

		/**
		 * Revocation endpoint of the token issuer, used when the mode is REMOTE.
		 */
		private String introspectionUri;

		/**
		 * Secret sent to the revocation endpoint to prove this application may ask.
		 */
		private String introspectionSecret;

		/**
		 * How long a remote revocation answer may be reused. A revocation therefore takes up to this
		 * long to be noticed by this application.
		 */
		private Duration cacheTtl = Duration.ofSeconds(30);

		public boolean isEnabled() {
			return this.enabled;
		}

		public void setEnabled(boolean enabled) {
			this.enabled = enabled;
		}

		public RevocationMode getMode() {
			return this.mode;
		}

		public void setMode(RevocationMode mode) {
			this.mode = mode;
		}

		public String getIntrospectionUri() {
			return this.introspectionUri;
		}

		public void setIntrospectionUri(String introspectionUri) {
			this.introspectionUri = introspectionUri;
		}

		public String getIntrospectionSecret() {
			return this.introspectionSecret;
		}

		public void setIntrospectionSecret(String introspectionSecret) {
			this.introspectionSecret = introspectionSecret;
		}

		public Duration getCacheTtl() {
			return this.cacheTtl;
		}

		public void setCacheTtl(Duration cacheTtl) {
			this.cacheTtl = cacheTtl;
		}

	}

}
