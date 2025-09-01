package com.quickmart.auth.jwt;

import java.security.Key;
import java.util.Date;
import java.util.List;
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
  public boolean validateToken(String token) {
    try {
      parseClaims(token, secretKey);
      return true;
    } catch (Exception e) {
      return false;
    }
  }

  public String getUsernameFromToken(String token){
    return parseClaims(token, secretKey).getSubject();
  }

  public List<String> getRolesFromToken(String token){
    return (List<String>) parseClaims(token, secretKey).get("roles");
  }

  private Claims parseClaims(String token, Key secretKey) {
    return Jwts.parserBuilder()
            .setSigningKey(secretKey)
            .build()
            .parseClaimsJws(token)
            .getBody();
  }

  private Claims createClaims(UserDetails userDetails) {
    Claims claims = Jwts.claims()
            .setSubject(userDetails.getUsername());
    claims.put("roles", userDetails.getRoles());
    return claims;
  }
}
