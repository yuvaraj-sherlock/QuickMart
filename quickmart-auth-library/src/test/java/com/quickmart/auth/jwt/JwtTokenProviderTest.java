package com.quickmart.auth.jwt;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.util.Base64;
import java.util.List;

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
        assert token != null && !token.isEmpty();
    }
}
