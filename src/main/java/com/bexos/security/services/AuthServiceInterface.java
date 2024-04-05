package com.bexos.security.services;

import com.bexos.security.requests.AuthRequest;
import com.bexos.security.requests.RegisterRequest;
import com.bexos.security.responses.AuthenticationResponse;

public interface AuthServiceInterface {
    AuthenticationResponse register(RegisterRequest request);
    AuthenticationResponse authenticate(AuthRequest request);
}
