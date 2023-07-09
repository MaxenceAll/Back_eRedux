package com.miniecomerce.eredux.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;

@Service
public class JwtService {

    @Value("${application.security.jwt.secret-key}")
    private String secretKey;
    @Value("${application.security.jwt.expiration}")
    private long jwtExpiration;
    @Value("${application.security.jwt.refresh-token.expiration}")
    private long refreshExpiration;

    public String extractCustomerEmail(String jwtToken) {
        return extractClaim(jwtToken, Claims::getSubject);
    }
    private Date extractExpiration(String jwtToken) {
        return extractClaim(jwtToken, Claims::getExpiration);
    }

    public <T> T extractClaim(String jwtToken, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(jwtToken);
        return claimsResolver.apply(claims);
    }

    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    public boolean isTokenValid(String jwtToken, UserDetails userDetails) {
        final String userEmail = extractCustomerEmail(jwtToken);
        return (userEmail.equals(userDetails.getUsername()) && !isTokenExpired(jwtToken));
    }

    private boolean isTokenExpired(String jwtToken) {

        return extractExpiration(jwtToken).before(new Date());
    }

    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        System.out.println("-- Je rentre dans generateToken");
        return buildToken(extraClaims, userDetails, jwtExpiration);
    }

    public String generateRefreshToken(UserDetails userDetails) {
        System.out.println("-- Je rentre dans generateRefreshToken");
        return buildToken(new HashMap<>(), userDetails, refreshExpiration);
    }


    private String buildToken(Map<String, Object> extraClaims, UserDetails userDetails, long expiration) {
        System.out.println("-- Je rentre dans buildToken");
        long currentTimeMillis = System.currentTimeMillis();
        Date issuedAt = new Date(currentTimeMillis);
        Date expirationDate = new Date(currentTimeMillis + expiration);

        return Jwts.builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(issuedAt)
                .setExpiration(expirationDate)
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }


    private Claims extractAllClaims(String jwtToken) {
        System.out.println("-- Je rentre dans extractAllClaims");
        return Jwts.parserBuilder()
                .setSigningKey(getSignInKey())
                .build().parseClaimsJws(jwtToken)
                .getBody();
    }

    private Key getSignInKey() {
        byte[] secretKeyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(secretKeyBytes);
    }

    public Claims parseToken(String token) throws JwtException {
        System.out.println("-- Je rentre dans parseToken");
        return Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

}
