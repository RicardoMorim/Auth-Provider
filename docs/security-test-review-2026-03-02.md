# Security and Test Review Report

Date: 2026-03-02  
Repository: Auth-Provider  
Scope: Static code/config/test review + runtime validation attempt

## Executive Summary

Security posture is **moderate**: core controls are present (cookie-based JWT auth, CSRF enabled, refresh token hashing/rotation/revocation, RBAC, and broad integration test coverage), but there are meaningful abuse-resilience and operational security gaps.

Test posture is **good in breadth** (39 surefire test reports with passing status in available artifacts), but there are alignment gaps between some unit tests and current runtime behavior in critical filter paths.

## Runtime Validation Status

- Attempted command: `./mvnw.cmd test`
- Result: **blocked** in this environment due to missing `JAVA_HOME`.
- Fallback used: existing test artifacts under `target/surefire-reports` and source-level validation.

## Findings by Severity

### High

1. **Rate limiting fails open when Redis errors occur**  
   Impact: During Redis outage or connectivity issues, abuse throttling is bypassed and requests are allowed.  
   Evidence:
   - `src/main/java/com/ricardo/auth/ratelimiter/RedisRateLimiter.java` (exception path returns `true`, logs “allowing the request”)

2. **Sensitive authentication metadata logged at info/warn level**  
   Impact: User identifiers and auth-event context are exposed to logs, increasing privacy and operational risk in centralized logging systems.  
   Evidence:
   - `src/main/java/com/ricardo/auth/controller/AuthController.java` (successful and failed login logging with sanitized email)
   - `src/main/java/com/ricardo/auth/service/RefreshTokenServiceImpl.java` (refresh-token lifecycle logs with user email)

### Medium

3. **Password reset HTTPS requirement exists in config but is not enforced in reset link generation**  
   Impact: Reset links may be generated with HTTP base URLs despite `requireHttps=true`, increasing interception/phishing risk.  
   Evidence:
   - `src/main/java/com/ricardo/auth/autoconfig/AuthProperties.java` (`baseUrl` default `http://localhost:8080`, `passwordReset.requireHttps=true`)
   - `src/main/java/com/ricardo/auth/service/PasswordResetServiceImpl.java` (`buildResetUrl` concatenates `baseUrl` without protocol enforcement)
   - Search confirmation: no code path uses `requireHttps` beyond property declaration.

4. **No explicit account lockout/brute-force tracking in auth flow**  
   Impact: Repeated credential stuffing may rely only on generic global rate limiting and not account-targeted controls.  
   Evidence:
   - `src/main/java/com/ricardo/auth/domain/user/User.java` (contains lock-related booleans)
   - Code search: no usage of failed-attempt counters/lock-window progression logic in main auth flow.
   - `src/main/java/com/ricardo/auth/autoconfig/AuthProperties.java` (`rate-limiter.maxRequests=150` default)

5. **Token blocklist stores raw tokens as in-memory/Redis keys**  
   Impact: Revoked token values are retained in directly recoverable form if memory dumps/Redis keyspace is exposed.  
   Evidence:
   - `src/main/java/com/ricardo/auth/blocklist/InMemoryTokenBlocklist.java` (map key is token string)
   - `src/main/java/com/ricardo/auth/blocklist/RedisTokenBlockList.java` (key format `revoked:<token>`)

6. **Dynamic SQL table-name concatenation from configuration**  
   Impact: Low-likelihood but avoidable hardening gap if configuration boundary is compromised/mismanaged.  
   Evidence:
   - `src/main/java/com/ricardo/auth/repository/PasswordResetToken/PostgreSqlPasswordResetTokenRepository.java` (queries built with `getTableName()` string concatenation/formatting)

### Low

7. **Documentation/runtime drift on JWT signing model**  
   Impact: Integrators may configure `jwt.secret` expecting HS256-style behavior while runtime uses RS256 via key provider.  
   Evidence:
   - `docs/properties-quick-reference.md` (multiple examples mark `jwt.secret` as required)
   - `src/main/java/com/ricardo/auth/service/JwtServiceImpl.java` (warns `jwt.secret` is ignored, uses `RsaKeyProvider`)
   - `src/main/java/com/ricardo/auth/autoconfig/AuthAutoConfiguration.java` (defaults to `InMemoryRsaKeyProvider`)

## Test Review

### Strengths

- Broad security integration coverage exists for authn/authz and endpoint access behavior:
  - `src/test/java/com/ricardo/auth/security/SecurityIntegrationTest.java`
  - `src/test/java/com/ricardo/auth/controller/AuthControllerRefreshTokenTest.java`
- Available surefire artifacts show passing suites for key areas:
  - `target/surefire-reports/com.ricardo.auth.security.SecurityIntegrationTest.txt`
  - `target/surefire-reports/com.ricardo.auth.controller.AuthControllerRefreshTokenTest.txt`
  - `target/surefire-reports/com.ricardo.auth.ratelimiter.RedisRateLimiterTest.txt`
- Existing report breadth: 39 `.txt` surefire reports in `target/surefire-reports`.

### Gaps / Mismatches

1. **`JwtAuthFilterTest` contains legacy Authorization-header assumptions**  
   Current filter extracts token from cookie (`access_token`), but several test cases still use `Authorization` header and often assert only `SecurityContext` nullity.  
   Evidence:
   - `src/main/java/com/ricardo/auth/security/JwtAuthFilter.java`
   - `src/test/java/com/ricardo/auth/security/JwtAuthFilterTest.java`

2. **No explicit regression test for Redis outage fail-open decision**  
   Existing rate limiter tests validate limits/concurrency/TTL behavior, but not outage policy enforcement.  
   Evidence:
   - `src/test/java/com/ricardo/auth/ratelimiter/RedisRateLimiterTest.java`

3. **No explicit test for `passwordReset.requireHttps` enforcement path**  
   Because enforcement code is not present, no tests verify secure reset-link construction under non-HTTPS base URLs.

4. **No explicit privacy/redaction assertions for auth logging**  
   Security-sensitive logging is present; tests do not appear to enforce logging policy constraints.

## Prioritized Remediation Themes

1. **Define and enforce outage security policy** for Redis-backed controls (strict mode should fail closed for abuse-critical paths).
2. **Reduce auth log sensitivity** (avoid direct user email/token-adjacent data at info/warn in high-volume flows).
3. **Enforce HTTPS invariants for password reset links** (`requireHttps` should be validated at runtime and in tests).
4. **Add account-centric brute-force protections** (per-account lock strategy or equivalent control in auth flow).
5. **Store token identifiers as hashes** in blocklist backends.
6. **Harden dynamic SQL surfaces** by constraining/validating configured table names against an allowlist.
7. **Align docs with RS256 key-provider model** and provide clear production key-management guidance.

## Assumptions and Uncertainties

- Redis fail-open may be an intentional availability tradeoff; review recommends strict-security posture by default.
- Production deployment may rely on reverse proxy TLS headers; ensure these are trusted and validated consistently.
- Runtime test re-execution in this environment was not possible due to missing Java toolchain configuration (`JAVA_HOME`).

## Key Files Reviewed

- `src/main/java/com/ricardo/auth/config/SecurityConfig.java`
- `src/main/java/com/ricardo/auth/security/JwtAuthFilter.java`
- `src/main/java/com/ricardo/auth/controller/AuthController.java`
- `src/main/java/com/ricardo/auth/service/RefreshTokenServiceImpl.java`
- `src/main/java/com/ricardo/auth/service/PasswordResetServiceImpl.java`
- `src/main/java/com/ricardo/auth/ratelimiter/RedisRateLimiter.java`
- `src/main/java/com/ricardo/auth/ratelimiter/RateLimiterFilter.java`
- `src/main/java/com/ricardo/auth/blocklist/InMemoryTokenBlocklist.java`
- `src/main/java/com/ricardo/auth/blocklist/RedisTokenBlockList.java`
- `src/main/java/com/ricardo/auth/repository/PasswordResetToken/PostgreSqlPasswordResetTokenRepository.java`
- `src/main/java/com/ricardo/auth/autoconfig/AuthProperties.java`
- `src/main/java/com/ricardo/auth/autoconfig/AuthAutoConfiguration.java`
- `src/main/java/com/ricardo/auth/service/JwtServiceImpl.java`
- `src/main/java/com/ricardo/auth/domain/user/User.java`
- `src/test/java/com/ricardo/auth/security/JwtAuthFilterTest.java`
- `src/test/java/com/ricardo/auth/security/SecurityIntegrationTest.java`
- `src/test/java/com/ricardo/auth/controller/AuthControllerRefreshTokenTest.java`
- `src/test/java/com/ricardo/auth/ratelimiter/RedisRateLimiterTest.java`
- `src/test/resources/application-test.yml`
- `docs/properties-quick-reference.md`
- `target/surefire-reports/*.txt`
