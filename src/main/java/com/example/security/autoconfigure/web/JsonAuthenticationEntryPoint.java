package com.example.security.autoconfigure.web;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

/**
 * Answers an unauthenticated request with a small JSON body instead of Spring Security's default
 * HTML page or {@code WWW-Authenticate} redirect, which is what a REST client expects.
 *
 * <p>The body is a constant, so this class needs no JSON library and therefore no assumption about
 * which object mapper the application has chosen.
 */
public class JsonAuthenticationEntryPoint implements AuthenticationEntryPoint {

	private static final String BODY = "{\"error\":\"unauthorized\",\"message\":\"A valid bearer token is required\"}";

	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException authException) throws IOException {
		response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);
		response.setCharacterEncoding(StandardCharsets.UTF_8.name());
		response.setHeader(HttpHeaders.WWW_AUTHENTICATE, "Bearer");
		response.getWriter().write(BODY);
	}

}
