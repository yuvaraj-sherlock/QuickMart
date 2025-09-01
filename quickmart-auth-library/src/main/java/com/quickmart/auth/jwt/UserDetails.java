package com.quickmart.auth.jwt;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@AllArgsConstructor
public class UserDetails {
    private final String username;
    private final List<String> roles;
}
