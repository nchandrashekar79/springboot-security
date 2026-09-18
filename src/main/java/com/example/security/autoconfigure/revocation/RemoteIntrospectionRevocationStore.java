package com.example.security.autoconfigure.revocation;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

import com.example.security.core.revocation.RevocationStore;
import com.example.security.core.revocation.RevocationStoreException;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.MediaType;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

/**
 * Asks the token issuer whether a token has been revoked.
 *
 * <p>This is the only correct option when several applications must agree on what has been
 * revoked, because an in-memory store cannot see revocations recorded elsewhere. The cost is a
 * network round trip, which is why answers are cached for a short period; the cache bounds how
 * long a revocation may go unnoticed, so {@code app.security.revocation.cache-ttl} is a
 * security-relevant setting rather than a performance knob alone.
 *
 * <p>If the issuer cannot be reached the store fails closed: an answer of "could not tell" is
 * treated as an error rather than as "not revoked".
 */
public class RemoteIntrospectionRevocationStore implements RevocationStore {

	private final RestClient restClient;

	private final String introspectionUri;

	private final String secret;

	private final Duration cacheTtl;

	private final Clock clock;

	private final Map<String, CachedDecision> cache = new ConcurrentHashMap<>();

	/**
	 * Create the store.
	 * @param restClient the client used to reach the issuer
	 * @param introspectionUri the issuer's revocation endpoint
	 * @param secret the shared secret proving this application may ask
	 * @param cacheTtl how long an answer may be reused
	 */
	public RemoteIntrospectionRevocationStore(RestClient restClient, String introspectionUri, String secret,
			Duration cacheTtl) {
		this(restClient, introspectionUri, secret, cacheTtl, Clock.systemUTC());
	}

	/**
	 * Create the store with an explicit clock, which makes cache expiry testable.
	 * @param restClient the client used to reach the issuer
	 * @param introspectionUri the issuer's revocation endpoint
	 * @param secret the shared secret proving this application may ask
	 * @param cacheTtl how long an answer may be reused
	 * @param clock the clock used to expire cached answers
	 */
	public RemoteIntrospectionRevocationStore(RestClient restClient, String introspectionUri, String secret,
			Duration cacheTtl, Clock clock) {
		this.restClient = Objects.requireNonNull(restClient, "restClient must not be null");
		if (introspectionUri == null || introspectionUri.isBlank()) {
			throw new IllegalArgumentException("introspectionUri must not be blank");
		}
		this.introspectionUri = introspectionUri;
		this.secret = secret;
		this.cacheTtl = Objects.requireNonNull(cacheTtl, "cacheTtl must not be null");
		this.clock = Objects.requireNonNull(clock, "clock must not be null");
	}

	@Override
	public boolean isRevoked(String tokenId) {
		if (tokenId == null || tokenId.isBlank()) {
			return false;
		}
		Instant now = this.clock.instant();
		CachedDecision cached = this.cache.get(tokenId);
		if (cached != null && cached.isFreshAt(now)) {
			return cached.revoked();
		}
		boolean revoked = !askIssuer(tokenId);
		this.cache.put(tokenId, new CachedDecision(revoked, now.plus(this.cacheTtl)));
		return revoked;
	}

	@Override
	public void purgeExpired() {
		Instant now = this.clock.instant();
		this.cache.entrySet().removeIf((entry) -> !entry.getValue().isFreshAt(now));
	}

	/**
	 * Number of cached answers currently held, including stale ones.
	 * @return the entry count
	 */
	public int cachedDecisions() {
		return this.cache.size();
	}

	private boolean askIssuer(String tokenId) {
		Map<String, Object> response;
		try {
			response = this.restClient.post()
				.uri(this.introspectionUri)
				.contentType(MediaType.APPLICATION_JSON)
				.headers((headers) -> {
					if (this.secret != null) {
						headers.set("X-Introspection-Secret", this.secret);
					}
				})
				.body(Map.of("tokenId", tokenId))
				.retrieve()
				.body(new ParameterizedTypeReference<Map<String, Object>>() {
				});
		}
		catch (RestClientException ex) {
			throw new RevocationStoreException(
					"Could not reach the revocation endpoint at " + this.introspectionUri + ": " + ex.getMessage(),
					ex);
		}
		Object revoked = (response != null) ? response.get("revoked") : null;
		if (!(revoked instanceof Boolean value)) {
			throw new RevocationStoreException(
					"The revocation endpoint at " + this.introspectionUri + " did not answer with a 'revoked' flag");
		}
		return value;
	}

	private record CachedDecision(boolean revoked, Instant expiresAt) {

		boolean isFreshAt(Instant now) {
			return this.expiresAt.isAfter(now);
		}

	}

}
