package com.quickmart.auth.jwt;

import java.security.Key;
import java.util.Date;
import java.util.Objects;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

public class JwtTokenProvider {

  private final Key secretKey;
  private final long tokenValidityInMs;

  public JwtTokenProvider(String secretKey, long tokenValidityInMs) {
    this.secretKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretKey));
    this.tokenValidityInMs = tokenValidityInMs;
  }

  public String generateToken(UserDetails userDetails) {
    Objects.requireNonNull(userDetails, "userDetails must not be null");
    return Jwts.builder()
            .setClaims(createClaims(userDetails))
            .setIssuer("QuickMart")
            .setIssuedAt(new Date(System.currentTimeMillis()))
            .setExpiration(new Date(System.currentTimeMillis() + tokenValidityInMs)) // 1 hour
            .signWith(SignatureAlgorithm.HS256, secretKey)
            .compact();
  }

  private Claims createClaims(UserDetails userDetails) {
    Claims claims = Jwts.claims();
    claims.setSubject(userDetails.getUsername());
    claims.put("roles", userDetails.getRoles()); // Add roles as a custom claim
    return claims;
  }
}
