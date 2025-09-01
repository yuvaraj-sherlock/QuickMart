package com.quickmart.auth.jwt;

import java.security.Key;
import java.util.Date;
import java.util.Objects;

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
            .setSubject(userDetails.getUsername())
            .claim("role", userDetails.getRoles())  // Add role as a custom claim
            .setIssuer("QuickMart")
            .setIssuedAt(new Date(System.currentTimeMillis()))
            .setExpiration(new Date(System.currentTimeMillis() + tokenValidityInMs)) // 1 hour
            .signWith(SignatureAlgorithm.HS256, secretKey)
            .compact();
  }
}
