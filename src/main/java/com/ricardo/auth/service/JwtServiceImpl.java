package com.ricardo.auth.service;

import com.ricardo.auth.autoconfig.AuthProperties;
import com.ricardo.auth.core.JwtService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import jakarta.annotation.PostConstruct;
import org.springframework.security.core.GrantedAuthority;

import javax.crypto.SecretKey;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * The type Jwt service.
 * Bean Creation is handled in the {@link com.ricardo.auth.autoconfig.AuthAutoConfiguration}
 */
public class JwtServiceImpl implements JwtService {
    private static final String ISSUER = "ricardo-auth";
    private static final String AUDIENCE = "ricardo-auth-client";

    private final String secret;
    private final long access_token_expiration;
    private SecretKey key;  // Changed from Key to SecretKey

    /**
     * Instantiates a new Jwt service.
     *
     * @param authProperties the auth properties
     */
    public JwtServiceImpl(AuthProperties authProperties) {
        this.secret = authProperties.getJwt().getSecret();
        this.access_token_expiration = authProperties.getJwt().getAccessTokenExpiration();

        // Validate secret is provided
        if (secret == null || secret.trim().isEmpty()) {
            throw new IllegalStateException(
                    "JWT secret is required but not configured. " +
                            "Please set 'ricardo.auth.jwt.secret' property."
            );
        }
    }

    /**
     * Init with enhanced secret validation.
     */
    @PostConstruct
    public void init() {
        // Enhanced secret validation
        if (secret == null || secret.trim().isEmpty()) {
            throw new IllegalStateException("JWT secret is required but not configured");
        }

        byte[] keyBytes;
        try {
            keyBytes = Decoders.BASE64.decode(this.secret);
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("JWT secret must be a valid Base64 encoded string", e);
        }

        // HMAC-SHA256 requires at least 256 bits (32 bytes)
        if (keyBytes.length < 32) {
            throw new IllegalStateException(
                    "JWT secret must be at least 256 bits (32 bytes) when Base64 decoded. " +
                            "Current length: " + keyBytes.length + " bytes"
            );
        }

        this.key = Keys.hmacShaKeyFor(keyBytes);
    }

    @Override
    public String generateAccessToken(String subject, Collection<? extends GrantedAuthority> authorities) {
        Map<String, Object> claims = new HashMap<>();
        List<String> roleStrings = authorities.stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());
        claims.put("roles", roleStrings);

        String tokenId = UUID.randomUUID().toString();
        claims.put("jti", tokenId);

        claims.put("token_type", "access");
        claims.put("iss", ISSUER);
        claims.put("aud", AUDIENCE);

        return Jwts.builder()
                .claims(claims)
                .subject(subject)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + access_token_expiration))
                .signWith(key, Jwts.SIG.HS256)
                .compact();
    }

    @Override
    public String extractSubject(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    @Override
    @SuppressWarnings("unchecked")
    public List<String> extractRoles(String token) {
        return extractClaim(token, claims -> (List<String>) claims.get("roles"));
    }

    @Override
    public boolean isTokenValid(String token, String email) {
        try {
            String tokenSubject = extractSubject(token);
            return email.equals(tokenSubject) && isTokenValid(token);
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public boolean isTokenValid(String token) {
        try {
            Claims claims = extractAllClaims(token);

            // Validate token type
            String tokenType = (String) claims.get("token_type");
            if (!"access".equals(tokenType)) {
                return false;
            }

            // More specific validation
            if (claims.getSubject() == null || claims.getSubject().trim().isEmpty()) {
                return false;
            }

            if (claims.getExpiration() == null) {
                return false;
            }

            if (!ISSUER.equals(claims.getIssuer())) {
                return false;
            }

            if (claims.getAudience().stream().noneMatch(AUDIENCE::equals)) {
                return false;
            }

            return !isTokenExpired(token);

        } catch (io.jsonwebtoken.ExpiredJwtException e) {
            // Token expired
            return false;
        } catch (SignatureException e) {
            // Invalid signature
            return false;
        } catch (io.jsonwebtoken.MalformedJwtException e) {
            // Malformed token
            return false;
        } catch (Exception e) {
            // Other errors
            return false;
        }
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}