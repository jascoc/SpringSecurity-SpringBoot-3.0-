package com.jasco.security.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service // because it manages bean
// we manage and parse the Jwt so here we got all the util methods
public class JwtService {

    private static final String SECRET_KEY = "4A614E645267556A586E3272357538782F413F4428472B4B6250655368566D59"; //base64

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject); // getSubject is a static method of Claims that return the username form a given token
    }

    // this is an util method that have access to all the method of Claims so, we can use it to get the info of the given token
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token); // taking data from the token
        return claimsResolver.apply(claims);
    }

    // generate the token with extractClaims and userDetails
    public String generateToken(
            Map<String, Object> extractClaims, // contains the claims
            UserDetails userDetails // contains the user info (you can generate a token only with the userDetails)
    ) {
        return Jwts
                .builder()
                .setClaims(extractClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis())) // setting the time the token is generated
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 24)) // setting the duration of the token to 24h
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact(); // this is the method that generate the token
    }

    // generate the token with only the userDetails
    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails); // new HashMap is taking the place of extractClaims
    }

    // method that validates the token
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token); // retrieves the username by the token
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }


    // method that checks if the token is not expired
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date()); // new Date() creates a date that is today
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration); // getting the expiration date using the getExpiration method of Claims
    }

    // parsing the token and setting
    private Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey()) //secret key to decode the token which ensure that the client has the right to do that
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY); // decodes the key that is in base 64
        return Keys.hmacShaKeyFor(keyBytes); // use the algorithm SHAKey and return the key
    }
}
