package com.example.springsecuritybyalibou.config;

import com.example.springsecuritybyalibou.user.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

//Managed Bean
@Service
public class JwtService {
    final SecretKey secretKey = Keys.hmacShaKeyFor("OOruAMEXYcrOjld+zFMXPDJ/IQLPOrKFs5fQPl5P4yg=".getBytes(StandardCharsets.UTF_8));

    //6- check if the token is not expired
    private boolean isTokenExpired(String token) {
        return extractClaim(token, Claims::getExpiration).before(new Date());
    }

    //5- implement method that can validate the token
    public boolean isTokenValid(String token, User user) {
        //we need to check if the token belong to user details
        //and also check that the token is not expired
        final String username = extractUsername(token);
        return username.equals(user.getUsername()) && !isTokenExpired(token);
    }



    public String generateToken(User user) {
        return generateToken(new HashMap<>(), user);
    }

    //4- Create Token with 3 component (Header , Payload , Signature)
    public String generateToken(Map<String, Object> extraClaims, User user) {
        //.builder() to create token
        return Jwts.builder()
                .claims(extraClaims)
                .subject(user.getUsername())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + (1000 * 60 * 60 *  24)))
                .signWith(secretKey, Jwts.SIG.HS256)
                .compact();
    }


    //3- Read
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    //to extract any data from Claim
    //2- Read
    public <T> T extractClaim(String token, Function<Claims, T> claimsFunction) {
        final Claims claims = extractAllClaims(token);
        return claimsFunction.apply(claims);
    }

    //1- Read
    private Claims extractAllClaims(String token) {
        //.parser() to read Claims
        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}
