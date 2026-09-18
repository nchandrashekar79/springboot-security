# springboot-security

A shared JWT security library for Spring Boot applications. A consuming application adds one
dependency and gets a stateless bearer-token security configuration, JWT issuing and verification,
and optional revocation checking.

Built for Spring Boot 4.1 and Java 21.

## Usage

Add the dependency, then point the library at your signing key and you are done:

```xml
<dependency>
  <groupId>com.example.security</groupId>
  <artifactId>springboot-security</artifactId>
  <version>1.0.0-SNAPSHOT</version>
</dependency>
```

```properties
# HS256: the same secret is used to sign and to verify.
app.security.jwt.secret=a-secret-value-that-is-long-enough-for-hs256-1234567890
```

The library then contributes:

- A `SecurityFilterChain` that requires a valid bearer token on every request, keeps no session
  state, and answers a rejected request with a small JSON body rather than an HTML login page.
- A `JwtDecoder` and a `JwtEncoder` built from the configured key material.
- A `TokenService` for issuing access and refresh tokens.

Everything is `@ConditionalOnMissingBean`. Declaring your own `SecurityFilterChain`, `JwtDecoder` or
`TokenService` replaces the corresponding default; there is no need to exclude anything.

## Configuration

All keys live under `app.security`. Spring Boot reserves `spring`, `server` and `management`, so the
library uses its own namespace.

| Key | Default | Purpose |
| --- | --- | --- |
| `app.security.enabled` | `true` | Whether the auto-configuration is active. |
| `app.security.permit-paths` | `/actuator/health/**` | Patterns reachable without a token. |
| `app.security.jwt.issuer` | `springboot-security` | Written to and required in the `iss` claim. |
| `app.security.jwt.audience` | `springboot-security-clients` | Written to and required in the `aud` claim. |
| `app.security.jwt.algorithm` | `HS256` | `HS256` for a shared secret, `RS256` for a key pair. |
| `app.security.jwt.secret` | none | Shared secret, at least 32 bytes. Required for `HS256`. |
| `app.security.jwt.key-id` | `springboot-security` | Published as the `kid` header and in the JWKS. |
| `app.security.jwt.private-key-location` | none | PEM PKCS#8 private key, needed only to sign with `RS256`. |
| `app.security.jwt.public-key-location` | none | PEM public key for `RS256`. Derived from the private key when omitted. |
| `app.security.jwt.jwk-set-uri` | none | JWKS endpoint for `RS256`. Takes precedence over the public key. |
| `app.security.jwt.access-token-ttl` | `15m` | Access token lifetime. Keep it short; see revocation below. |
| `app.security.jwt.refresh-token-ttl` | `7d` | Refresh token lifetime. |
| `app.security.jwt.clock-skew` | `60s` | Tolerance on the `exp` and `nbf` claims. |
| `app.security.jwt.authorities-claim` | `roles` | Claim holding the caller's authorities. |
| `app.security.jwt.authority-prefix` | empty | Prefix applied to each authority. Empty because issued authorities are already complete. |
| `app.security.jwt.require-access-token-type` | `true` | Refuse a refresh token presented as a bearer token. |
| `app.security.revocation.enabled` | `false` | Whether revoked tokens are rejected. |
| `app.security.revocation.mode` | `LOCAL` | `LOCAL` keeps decisions in this JVM; `REMOTE` asks the issuer. |
| `app.security.revocation.introspection-uri` | none | Issuer endpoint used when the mode is `REMOTE`. |
| `app.security.revocation.introspection-secret` | none | Shared secret proving this application may ask. |
| `app.security.revocation.cache-ttl` | `30s` | How long a remote answer is reused. |

### Extending instead of replacing

To add authorization rules while keeping the library's reasoning intact, register a
`JwtSecurityCustomizer`. Rules added this way are evaluated before the catch-all
"authenticated" rule, so they take effect. `JwtAuthorizationCustomizer` does the same for the
authorization manager.

## Revocation, and what it costs

A JWT is self-contained, so a token remains valid until it expires no matter what the issuer later
decides. True revocation therefore needs shared state, and the library does not pretend otherwise:

- `app.security.revocation.enabled=false` (the default) means no revocation at all. Access tokens
  are trusted until they expire, which is why the default access token lifetime is 15 minutes.
- `mode=LOCAL` keeps revocations in the current JVM. It is correct only when one process both issues
  and consumes the tokens. With several applications, each one would keep its own list and revoke
  nothing that the others know about.
- `mode=REMOTE` asks the issuer on every request, with a short cache. This is the only mode that
  works across applications. The cache bounds how long a revocation goes unnoticed, so
  `cache-ttl` is a security setting, not just a performance knob. If the issuer is unreachable the
  check fails closed: "could not tell" is treated as an error, not as "not revoked".

## Layout

One module. The packages preserve the original layering because that boundary is real:

- `com.example.security.core` — token issuing, verification and the revocation SPI. No Spring Boot
  or servlet dependency, so it stays unit-testable on its own.
- `com.example.security.autoconfigure` — auto-configuration, `app.security.*` properties, the
  default filter chain, and the JSON error responses.

Auto-configuration is registered in
`src/main/resources/META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports`,
so no component scanning of this library is required or performed.

This module is a library, not an application: `spring-boot-maven-plugin` is intentionally absent, so
the jar keeps a normal layout and stays usable as a dependency.

## Build

```bash
mvn clean install     # requires Maven 3.9+ and JDK 21
mvn test
```

The tests are arranged in two layers. Unit tests cover token issuing and verification directly.
Then, rather than asserting on bean wiring alone, the web tests start a real application context and
make real HTTP requests, so the filter chain, the JSON error responses and the token-type check are
all exercised over the wire.
