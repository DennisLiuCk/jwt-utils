package com.example.jwt;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import java.util.HashMap;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.*;

class JwtUtilsTest {
    private JwtUtils jwtUtils;
    private static final long VALIDITY = 3600000; // 1 hour

    @BeforeEach
    void setUp() {
        // Initialize with auto-generated RS256 key pair
        jwtUtils = new JwtUtils(VALIDITY);
    }

    @Test
    void testGenerateAndValidateToken() {
        String subject = "testUser";
        String token = jwtUtils.generateToken(subject);
        
        System.out.println("Basic token: " + token);
        
        assertTrue(jwtUtils.validateToken(token));
        assertEquals(subject, jwtUtils.getSubject(token));
    }

    @Test
    void testGenerateTokenWithClaims() {
        String subject = "testUser";
        Map<String, Object> claims = new HashMap<>();
        claims.put("role", "ADMIN");
        claims.put("email", "test@example.com");
        
        String token = jwtUtils.generateToken(subject, claims);

        System.out.println("Token with claims: " + token);
        
        assertTrue(jwtUtils.validateToken(token));
        assertEquals(subject, jwtUtils.getSubject(token));
        assertEquals("ADMIN", jwtUtils.getAllClaims(token).get("role"));
        assertEquals("test@example.com", jwtUtils.getAllClaims(token).get("email"));
    }

    @Test
    void testInvalidToken() {
        String invalidToken = "invalid.token.here";
        assertFalse(jwtUtils.validateToken(invalidToken));
    }

    @Test
    void testFromBase64Keys() throws Exception {
        // First, get Base64 keys from an existing instance
        String base64PrivateKey = jwtUtils.getBase64PrivateKey();
        String base64PublicKey = jwtUtils.getBase64PublicKey();

        System.out.println("Base64 private key: " + base64PrivateKey);
        System.out.println("Base64 public key: " + base64PublicKey);
        System.out.println("\nPublic Key in PEM format (use this in jwt.io):\n" + jwtUtils.getPublicKeyPEM());

        // Create new instance using these Base64 keys
        JwtUtils newJwtUtils = JwtUtils.fromBase64Keys(base64PrivateKey, base64PublicKey, VALIDITY);

        // Test token generation and validation with the new instance
        String subject = "testUser";
        String token = newJwtUtils.generateToken(subject);

        System.out.println("Token with Base64 keys: " + token);

        // Token should be valid and contain correct subject
        assertTrue(newJwtUtils.validateToken(token));
        assertEquals(subject, newJwtUtils.getSubject(token));

        // Token should also be valid with original jwtUtils instance
        assertTrue(jwtUtils.validateToken(token));
        assertEquals(subject, jwtUtils.getSubject(token));
    }

    @Test
    void testFromBase64KeysWithInvalidKeys() {
        // Test with invalid Base64 strings
        String invalidBase64 = "invalid-base64-string";
        
        Exception exception = assertThrows(Exception.class, () -> {
            JwtUtils.fromBase64Keys(invalidBase64, invalidBase64, VALIDITY);
        });
        
        assertTrue(exception.getMessage().contains("Illegal base64"));
    }
}
