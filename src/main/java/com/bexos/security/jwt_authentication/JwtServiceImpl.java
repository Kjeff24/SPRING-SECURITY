package com.bexos.security.jwt_authentication;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtServiceImpl implements JwtInterface{
    private static final String SECRET_KEY = "hVax04fNbyDTGu6Kp+wG7JUFdrTAXgtQVJNtK7yD8zCmL9Wu6X+Lp/o/OgkFf8Zi";

    // Extracts username from a JWT token
    public String extractUsername(CharSequence token){
        return extractClaim(token, Claims::getSubject);
    }

    // Extracts all claims from a JWT token
    private Claims extractAllClaims(CharSequence token) {
        return Jwts
                .parser()
                .verifyWith(getSignKey()) // Verifies the token's signature
                .build()
                .parseSignedClaims(token) // Parses the signed claims from the token
                .getPayload(); // Retrieves the payload of the token

    }

    // Extracts a specific claim from a JWT token
    public <T> T extractClaim(CharSequence token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    // Generates a JWT token with only user details
    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        return generateToken(claims, userDetails);
    }

    // Generates a JWT token with additional claims and user details
    public String generateToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails
    ){
        return Jwts
                .builder()
                .claims(extraClaims) // Sets additional claims
                .subject(userDetails.getUsername()) // Sets the subject of the token
                .issuedAt(new Date(System.currentTimeMillis())) // Sets the token's issued time
                .expiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24)) // Sets the token's expiration time
                .signWith(getSignKey(), Jwts.SIG.HS256) // Signs the token with the specified signature algorithm and key
                .compact(); // Builds the token in compact form

    }

    // Check if token is valid
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return(username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    // check if token is expired
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    // Get expiration date
    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    // Retrieves the signing key for JWT
    private SecretKey getSignKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY); // Decodes the secret key from base64 encoding
        return Keys.hmacShaKeyFor(keyBytes); // Generates an HMAC SHA cryptographic key from the decoded bytes
    }
}
