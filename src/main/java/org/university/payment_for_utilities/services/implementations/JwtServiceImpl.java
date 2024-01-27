package org.university.payment_for_utilities.services.implementations;

import io.github.cdimascio.dotenv.Dotenv;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.NonNull;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.university.payment_for_utilities.exceptions.InvalidInputDataException;
import org.university.payment_for_utilities.services.interfaces.JwtService;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtServiceImpl implements JwtService {
    private final String secretKey;
    private final long jwtExpiration;
    private final long refreshExpiration;


    public JwtServiceImpl() {
        var dotenv = Dotenv.configure().load();

        this.secretKey = dotenv.get("SECURITY_KEY");
        this.jwtExpiration = Long.parseLong(dotenv.get("EXPIRATION"));
        this.refreshExpiration = Long.parseLong(dotenv.get("REFRESH_TOKEN_EXPIRATION"));
    }

    @Override
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    @Override
    public <T> T extractClaim(String token, @NonNull Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    @Override
    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    @Override
    public String generateToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails
    ) {
        return buildToken(extraClaims, userDetails, jwtExpiration);
    }

    @Override
    public String generateRefreshToken(UserDetails userDetails) {
        return buildToken(new HashMap<>(), userDetails, refreshExpiration);
    }

    private String buildToken(
            Map<String, Object> extraClaims,
            @NonNull UserDetails userDetails,
            long expiration
    ) throws InvalidInputDataException, NullPointerException {
        return Jwts
                .builder()
                .claims().add(extraClaims).and()
                .subject(userDetails.getUsername())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSecretKey())
                .compact();
    }

    @Override
    public boolean isTokenValid(String token, @NonNull UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    private Claims extractAllClaims(String token) {
        var jwtParser = Jwts
                .parser()
                .verifyWith(getSecretKey())
                .build();

        return jwtParser
                .parseSignedClaims(token)
                .getPayload();
    }

    private @NonNull SecretKey getSecretKey() {
        return Keys
                .hmacShaKeyFor(
                        secretKey.getBytes(StandardCharsets.UTF_8)
                );
    }
}
