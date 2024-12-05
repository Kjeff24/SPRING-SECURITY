package com.bexos.security.requests;

// Data carrier for registration
public record RegisterRequest(
        String firstName,
        String lastName,
        String email,
        String password
) {}
