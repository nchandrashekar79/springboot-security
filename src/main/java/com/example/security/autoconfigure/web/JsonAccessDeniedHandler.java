package com.example.security.autoconfigure.web;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

/**
 * Answers an authenticated but unauthorized request with a JSON body.
 *
 * <p>The message deliberately does not say what would have been required, so that a caller cannot
 * use the response to map out the authorization rules.
 */
public class JsonAccessDeniedHandler implements AccessDeniedHandler {

	private static final String BODY = "{\"error\":\"forbidden\",\"message\":\"The presented token does not grant access to this resource\"}";

	@Override
	public void handle(HttpServletRequest request, HttpServletResponse response,
			AccessDeniedException accessDeniedException) throws IOException {
		response.setStatus(HttpServletResponse.SC_FORBIDDEN);
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);
		response.setCharacterEncoding(StandardCharsets.UTF_8.name());
		response.getWriter().write(BODY);
	}

}
