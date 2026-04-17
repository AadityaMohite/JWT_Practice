package com.Aadi.service;

import java.nio.charset.StandardCharsets;
import java.time.Year;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import javax.crypto.SecretKey;

import org.springframework.security.core.userdetails.UserDetails;

import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

import io.jsonwebtoken.security.Keys;

@Service
public class JWTUtil {
	
	//Create token , Validate Token , SecretKey

	private static final String SECRET_KEY = "mysecretkeymysecretkeymysecretkey12345";

	private SecretKey getSigningKey() { //secret key ko convert karta ha real usable key mein
	    return Keys.hmacShaKeyFor(SECRET_KEY.getBytes(StandardCharsets.UTF_8));
	}

	
	//JWT - Signature , Payload , Subject
	public String extractUsername(String token) {  //ye method token se username nikalata hai
	    return Jwts.parser()
	            .verifyWith(getSigningKey())
	            .build()
	            .parseSignedClaims(token)
	            .getPayload()
	            .getSubject();
	}

    public Date extractExpiration(String token) {  //ye method token kab expire hoga ye bata ta hai
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) { //ha ek generic extractor ahe kahi pan extract karto 
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }
    private Claims extractAllClaims(String token) { //token aatala data sagala dhakhavto
        return Jwts.parser()
                .verifyWith(getSigningKey())   
                .build()                       
                .parseSignedClaims(token)     
                .getPayload();                
    }

    private Boolean isTokenExpired(String token) { // hi method check karte ki token expired zhal ahe ki nahi
        return extractExpiration(token).before(new Date());
    }

    public String generateToken(UserDetails userDetails) {  // he method token la genrate karato
        Map<String, Object> claims = new HashMap<>();
        return createToken(claims, userDetails.getUsername());
    }

    private String createToken(Map<String, Object> claims, String subject) { // he method token la create karte

        return Jwts.builder()
                .claims(claims)                 // ✅ add custom claims
                .subject(subject)               // ✅ use subject param
                .issuedAt(new Date())            // ✅ token issue time
                .expiration(new Date(System.currentTimeMillis() + 1000 * 180)) // 1 minute
                .signWith(getSigningKey())       // ✅ HS256 automatically
                .compact();
    }

    public boolean validateToken(String token) { // he method token validate ahe ka nahi he check karat
        try {
            Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }


}
