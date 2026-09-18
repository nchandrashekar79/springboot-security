package com.example.security.autoconfigure.web;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import com.example.security.core.revocation.RevocationStore;
import com.example.security.core.token.TokenType;

import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Applies the checks that go beyond a token's signature, issuer, audience and expiry.
 *
 * <p>Runs after the bearer token filter, so by this point the token is known to be authentic and
 * only the "should this token be honoured here" questions remain:
 *
 * <ul>
 * <li>A refresh token must not work as a bearer credential. A refresh token is signed with the same
 * key and lives longer, so without this check exchanging a long lived credential would hand out
 * everything an access token grants.</li>
 * <li>A revoked token must be refused, when revocation checking is switched on.</li>
 * </ul>
 *
 * <p>Both failures produce the same 401 response a missing token would, so a caller learns nothing
 * about why it was rejected.
 */
public class JwtBearerTokenValidationFilter extends OncePerRequestFilter {

	private final AuthenticationEntryPoint authenticationEntryPoint;

	private final boolean requireAccessTokenType;

	private final RevocationStore revocationStore;

	/**
	 * Create the filter.
	 * @param authenticationEntryPoint the entry point used to answer a rejected request
	 * @param requireAccessTokenType whether a token must declare itself an access token
	 * @param revocationStore where revocation decisions come from, or {@code null} when revocation
	 * checking is switched off
	 */
	public JwtBearerTokenValidationFilter(AuthenticationEntryPoint authenticationEntryPoint,
			boolean requireAccessTokenType, RevocationStore revocationStore) {
		this.authenticationEntryPoint = authenticationEntryPoint;
		this.requireAccessTokenType = requireAccessTokenType;
		this.revocationStore = revocationStore;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (authentication instanceof JwtAuthenticationToken jwtAuthentication) {
			Jwt jwt = jwtAuthentication.getToken();
			if (this.requireAccessTokenType && !isAccessToken(jwt)) {
				reject(request, response, "The presented token is not an access token");
				return;
			}
			if (this.revocationStore != null && this.revocationStore.isRevoked(jwt.getId())) {
				reject(request, response, "The token has been revoked");
				return;
			}
		}
		filterChain.doFilter(request, response);
	}

	/**
	 * Read the claim defensively: a forged or foreign token may carry a value of the wrong type,
	 * and treating that as "not an access token" is both safe and simpler than failing to cast.
	 */
	private static boolean isAccessToken(Jwt jwt) {
		Object declared = jwt.getClaim(TokenType.CLAIM_NAME);
		return (declared instanceof String value) && TokenType.ACCESS.claimValue().equals(value);
	}

	private void reject(HttpServletRequest request, HttpServletResponse response, String reason)
			throws IOException, ServletException {
		SecurityContextHolder.clearContext();
		this.authenticationEntryPoint.commence(request, response,
				new InsufficientAuthenticationException(reason));
	}

}
