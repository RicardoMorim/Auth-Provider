package com.ricardo.auth.service;

import com.ricardo.auth.autoconfig.AuthProperties;
import com.ricardo.auth.core.JwtService;
import com.ricardo.auth.core.RsaKeyProvider;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.SignatureException;
import org.springframework.security.core.GrantedAuthority;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

public class JwtServiceImpl implements JwtService {

    private static final String ISSUER = "ricardo-auth";
    private static final String AUDIENCE = "ricardo-auth-client";

    private final long accessTokenExpiration;
    private final RsaKeyProvider keyProvider;

    public JwtServiceImpl(AuthProperties authProperties, RsaKeyProvider keyProvider) {
        this.accessTokenExpiration = authProperties.getJwt().getAccessTokenExpiration();
        this.keyProvider = keyProvider;
    }


    @Override
    public String generateAccessToken(
            String subject,
            Collection<? extends GrantedAuthority> authorities
    ) {
        Map<String, Object> claims = new HashMap<>();

        List<String> roles = authorities.stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        claims.put("roles", roles);
        claims.put("jti", UUID.randomUUID().toString());
        claims.put("token_type", "access");
        claims.put("iss", ISSUER);
        claims.put("aud", AUDIENCE);

        return Jwts.builder()
                .claims(claims)
                .subject(subject)
                .issuedAt(new Date())
                .expiration(new Date(
                        System.currentTimeMillis() + accessTokenExpiration
                ))
                .signWith(keyProvider.getPrivateKey(), Jwts.SIG.RS256)
                .compact();
    }


    @Override
    public String extractSubject(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    @Override
    @SuppressWarnings("unchecked")
    public List<String> extractRoles(String token) {
        return extractClaim(token,
                claims -> (List<String>) claims.get("roles"));
    }

    @Override
    public boolean isTokenValid(String token, String email) {
        try {
            String subject = extractSubject(token);
            return email.equals(subject) && isTokenValid(token);
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public boolean isTokenValid(String token) {
        try {
            Claims claims = extractAllClaims(token);

            if (!"access".equals(claims.get("token_type")))
                return false;

            if (claims.getSubject() == null || claims.getSubject().trim().isEmpty())
                return false;

            if (claims.getExpiration() == null)
                return false;

            if (!ISSUER.equals(claims.getIssuer()))
                return false;

            if (claims.getAudience().stream().noneMatch(AUDIENCE::equals))
                return false;

            return !claims.getExpiration().before(new Date());

        } catch (io.jsonwebtoken.ExpiredJwtException e) {
            return false;
        } catch (SignatureException e) {
            return false;
        } catch (io.jsonwebtoken.MalformedJwtException e) {
            return false;
        } catch (Exception e) {
            return false;
        }
    }


    @Override
    public PublicKey getPublicKey() {
        return keyProvider.getPublicKey();
    }


    private <T> T extractClaim(
            String token,
            Function<Claims, T> resolver) {
        Claims claims = extractAllClaims(token);
        return resolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(keyProvider.getPublicKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}