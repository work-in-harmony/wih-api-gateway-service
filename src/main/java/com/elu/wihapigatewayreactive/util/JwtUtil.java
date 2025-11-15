package com.elu.wihapigatewayreactive.util;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.List;
import java.util.function.Function;
import java.util.stream.Collectors;

@Component
public class JwtUtil {

    @Value("${jwt.secret.key}")
    private String SECRET_KEY;

    public <T> T extractClaimByToken(
            String token,
            Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .setSigningKey(SECRET_KEY)
                .parseClaimsJws(token)
                .getBody();
    }

    public String extractEmail(String token) {
        return extractClaimByToken(token, Claims::getSubject);
    }

    public Date extractExpiration(String token) {
        return extractClaimByToken(token, Claims::getExpiration);
    }

    public Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    public List<String> extractRoles(String token) {
        Claims claims = extractAllClaims(token);
        // when you stored a JSON array of roles
        List<?> raw = claims.get("roles", List.class);
        return raw == null
                ? List.of()
                : raw.stream().map(Object::toString).collect(Collectors.toList());
    }

    public Boolean validateToken(String token) {
        try {
            Claims claims = extractAllClaims(token);
            String email = extractEmail(token);
            return !claims.getExpiration().before(new Date());

        } catch (JwtException e) {
            return false;
        }
    }


}