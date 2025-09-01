package com.quickmart.auth.jwt;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class JwtTokenProviderTest {

  private JwtTokenProvider jwtTokenProvider;
  private final String secret = Base64.getEncoder().encodeToString("mysecretkeymysecretkeymysecretkey12".getBytes());

  @BeforeEach
  void setUp() {
    jwtTokenProvider = new JwtTokenProvider(secret, 3600000);
  }

  @Test
  void generateToken_shouldReturnValidJwt() {
    UserDetails userDetails = Mockito.mock(UserDetails.class);
    Mockito.when(userDetails.getUsername()).thenReturn("testuser");
    Mockito.when(userDetails.getRoles()).thenReturn(List.of("ROLE_USER"));
    String token = jwtTokenProvider.generateToken(userDetails);
    assertNotNull(token);
    assertFalse(token.isEmpty());
  }

  @Test
  void validateToken_shouldReturnTrueForValidToken() {
    UserDetails userDetails = Mockito.mock(UserDetails.class);
    Mockito.when(userDetails.getUsername()).thenReturn("testuser");
    Mockito.when(userDetails.getRoles()).thenReturn(List.of("ROLE_USER"));
    String token = jwtTokenProvider.generateToken(userDetails);

    boolean isValid = jwtTokenProvider.validateToken(token);

    assertTrue(isValid);
  }

  @Test
  void validateToken_shouldReturnFalseForInvalidToken() {
    String invalidToken = "invalid.token.value";

    boolean isValid = jwtTokenProvider.validateToken(invalidToken);

    assertFalse(isValid);
  }

  @Test
  void getUsernameFromToken_shouldReturnSubject() {
    UserDetails userDetails = Mockito.mock(UserDetails.class);
    Mockito.when(userDetails.getUsername()).thenReturn("testuser");
    Mockito.when(userDetails.getRoles()).thenReturn(List.of("ROLE_USER"));
    String token = jwtTokenProvider.generateToken(userDetails);

    String username = jwtTokenProvider.getUsernameFromToken(token);

    assertEquals("testuser", username);
  }

  @Test
  void getRolesFromToken_shouldReturnRoles() {
    UserDetails userDetails = Mockito.mock(UserDetails.class);
    Mockito.when(userDetails.getUsername()).thenReturn("testuser");
    Mockito.when(userDetails.getRoles()).thenReturn(List.of("ROLE_USER", "ROLE_ADMIN"));
    String token = jwtTokenProvider.generateToken(userDetails);

    List<String> roles = jwtTokenProvider.getRolesFromToken(token);

    assertEquals(List.of("ROLE_USER", "ROLE_ADMIN"), roles);
  }

  @Test
  void parseClaims_shouldThrowExceptionForInvalidToken() {
    assertThrows(Exception.class, () -> {
      jwtTokenProvider.getUsernameFromToken("invalid.token.value");
    });
  }

  @Test
  void generateToken_shouldThrowExceptionForNullUserDetails() {
    assertThrows(NullPointerException.class, () -> {
      jwtTokenProvider.generateToken(null);
    });
  }
}