package org.university.payment_for_utilities.services.implementations;

import io.jsonwebtoken.Claims;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import io.jsonwebtoken.security.SignatureException;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@SpringBootTest
class JwtServiceTest {
    private static final String EXPECTED_USERNAME = "username";
    private static final UserDetails USER_DETAILS = User
            .withUsername(EXPECTED_USERNAME)
            .password("password")
            .roles("USER")
            .build();

    @InjectMocks
    private JwtServiceImpl jwtService;

    @Test
    @DisplayName("Checking the generation of a token for work.")
    void testGenerateTokenWithUserDetailsCorrect() {
        var token = jwtService.generateToken(USER_DETAILS);

        assertThat(token)
                .isNotNull()
                .isNotBlank();
    }

    @Test
    @DisplayName("Checking for a NullPointerException when generating a token when null was passed in the parameters.")
    void testGenerateTokenWithUserDetailsThrowNullPointerException() {
        assertThrows(NullPointerException.class,
                () -> jwtService.generateToken(null)
        );
    }

    @Test
    @DisplayName("")
    void testGenerateTokenWithExtractClaimsAndUserDetailsCorrect() {
        Map<String, Object> extraClaims = new HashMap<>();
        extraClaims.put("role", "ADMIN");

        var token = jwtService.generateToken(extraClaims, USER_DETAILS);

        assertThat(token)
                .isNotNull()
                .isNotBlank();
    }

    @Test
    @DisplayName("Checking the generation of a refresh token for work.")
    void testGenerateRefreshTokenCorrect() {
        var token = jwtService.generateRefreshToken(USER_DETAILS);

        assertThat(token)
                .isNotNull()
                .isNotBlank();
    }

    @Test
    @DisplayName("Checking for a NullPointerException when generating a refresh token when null was passed in the parameters.")
    void testGenerateRefreshTokenCorrectThrowNullPointerException() {
        assertThrows(NullPointerException.class,
                () -> jwtService.generateRefreshToken(null)
        );
    }

    @Test
    @DisplayName("Checking for the correct extraction of the username from the generated token.")
    void testExtractUsernameCorrect() {
        var token = jwtService.generateToken(USER_DETAILS);
        var actualUsername = jwtService.extractUsername(token);

        assertEquals(EXPECTED_USERNAME, actualUsername);
    }

    @Test
    @DisplayName("Checks for an exception when the JWT signature does not match the locally computed signature.")
    void testExtractUsernameFailJwtSignature() {
        var token = "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJ1c2VybmFtZSIsImlhdCI6MTcwNjM0OTA5OSwiZXhwIjoxNzA2NDM1NDk5fQ.H9s9etukjdCC";

        assertThrows(SignatureException.class,
                () -> jwtService.extractUsername(token)
        );
    }

    @Test
    @DisplayName("Checking the method to extract specific requirements from a given JWT.")
    void testExtractClaimCorrect() {
        var expected = USER_DETAILS.getUsername();
        var token = jwtService.generateToken(USER_DETAILS);
        var mockClaims = mock(Claims.class);

        doReturn(expected)
                .when(mockClaims)
                .getSubject();

        var actualClaim = jwtService.extractClaim(token, Claims::getSubject);
        assertEquals(expected, actualClaim);
    }

    @Test
    @DisplayName("Verify that the token matches the user's data.")
    void testIsTokenValidCorrect() {
        var token = jwtService.generateToken(USER_DETAILS);
        assertTrue(jwtService.isTokenValid(token, USER_DETAILS));
    }
}
