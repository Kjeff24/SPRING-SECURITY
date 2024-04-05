package com.bexos.security.requests;

// Data Carrier for authentication request
public record AuthRequest(
        String email,
        String password
) {}
