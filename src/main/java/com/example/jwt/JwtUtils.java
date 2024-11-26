package com.example.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import java.security.KeyPair;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.Map;
import java.util.function.Function;

/**
 * Utility class for handling JWT token operations with RS256 support.
 */
public class JwtUtils {
    private final PrivateKey privateKey;
    private final PublicKey publicKey;
    private final long validityInMilliseconds;

    /**
     * Initialize JwtUtils with RS256 key pair and token validity duration.
     *
     * @param validityInMilliseconds The token validity duration in milliseconds
     */
    public JwtUtils(long validityInMilliseconds) {
        KeyPair keyPair = Keys.keyPairFor(SignatureAlgorithm.RS256);
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
        this.validityInMilliseconds = validityInMilliseconds;
    }

    /**
     * Initialize JwtUtils with provided RS256 key pair and token validity duration.
     *
     * @param privateKey The private key for signing
     * @param publicKey The public key for verification
     * @param validityInMilliseconds The token validity duration in milliseconds
     */
    public JwtUtils(PrivateKey privateKey, PublicKey publicKey, long validityInMilliseconds) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
        this.validityInMilliseconds = validityInMilliseconds;
    }

    /**
     * Get the public key used for token verification.
     *
     * @return The public key
     */
    public PublicKey getPublicKey() {
        return publicKey;
    }

    /**
     * Generate a JWT token with custom claims.
     *
     * @param subject The subject of the token (usually user ID or username)
     * @param claims Additional claims to include in the token
     * @return The generated JWT token
     */
    public String generateToken(String subject, Map<String, Object> claims) {
        long now = System.currentTimeMillis();
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(new Date(now))
                .setExpiration(new Date(now + validityInMilliseconds))
                .signWith(privateKey, SignatureAlgorithm.RS256)
                .compact();
    }

    /**
     * Generate a simple JWT token with just a subject.
     *
     * @param subject The subject of the token
     * @return The generated JWT token
     */
    public String generateToken(String subject) {
        long now = System.currentTimeMillis();
        return Jwts.builder()
                .setSubject(subject)
                .setIssuedAt(new Date(now))
                .setExpiration(new Date(now + validityInMilliseconds))
                .signWith(privateKey, SignatureAlgorithm.RS256)
                .compact();
    }

    /**
     * Validate a JWT token.
     *
     * @param token The token to validate
     * @return true if the token is valid, false otherwise
     */
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(publicKey)
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Extract the subject from a JWT token.
     *
     * @param token The JWT token
     * @return The subject from the token
     */
    public String getSubject(String token) {
        return getClaim(token, Claims::getSubject);
    }

    /**
     * Extract the expiration date from a JWT token.
     *
     * @param token The JWT token
     * @return The expiration date
     */
    public Date getExpirationDate(String token) {
        return getClaim(token, Claims::getExpiration);
    }

    /**
     * Extract a specific claim from a JWT token.
     *
     * @param token The JWT token
     * @param claimsResolver Function to extract the desired claim
     * @param <T> The type of the claim
     * @return The extracted claim
     */
    public <T> T getClaim(String token, Function<Claims, T> claimsResolver) {
        Claims claims = getAllClaims(token);
        return claimsResolver.apply(claims);
    }

    /**
     * Extract all claims from a JWT token.
     *
     * @param token The JWT token
     * @return All claims from the token
     */
    public Claims getAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(publicKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    /**
     * Create a JwtUtils instance from Base64-encoded key strings.
     *
     * @param base64PrivateKey The Base64-encoded private key
     * @param base64PublicKey The Base64-encoded public key
     * @param validityInMilliseconds The token validity duration in milliseconds
     * @return A new JwtUtils instance
     * @throws Exception if the keys cannot be decoded
     */
    public static JwtUtils fromBase64Keys(String base64PrivateKey, String base64PublicKey, long validityInMilliseconds) throws Exception {
        byte[] privateKeyBytes = Base64.getDecoder().decode(base64PrivateKey);
        byte[] publicKeyBytes = Base64.getDecoder().decode(base64PublicKey);
        
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
        
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
        
        return new JwtUtils(privateKey, publicKey, validityInMilliseconds);
    }

    /**
     * Get the Base64-encoded representation of the public key.
     *
     * @return The Base64-encoded public key
     */
    public String getBase64PublicKey() {
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }

    /**
     * Get the Base64-encoded representation of the private key.
     *
     * @return The Base64-encoded private key
     */
    public String getBase64PrivateKey() {
        return Base64.getEncoder().encodeToString(privateKey.getEncoded());
    }

    /**
     * Get the public key in PEM format, suitable for jwt.io verification.
     *
     * @return The public key in PEM format
     */
    public String getPublicKeyPEM() {
        String base64Key = Base64.getEncoder().encodeToString(publicKey.getEncoded());
        return "-----BEGIN PUBLIC KEY-----\n" +
               base64Key + "\n" +
               "-----END PUBLIC KEY-----";
    }
}
