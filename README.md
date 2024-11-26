# JWT Utils

A Java utility library for handling JWT (JSON Web Token) operations with RS256 (RSA) signature support. This library provides a simple and secure way to generate, validate, and manage JWT tokens using RSA key pairs.

## Features

- RS256 (RSA) signature algorithm support
- Automatic key pair generation
- Custom key pair support
- Token generation with custom claims
- Token validation and verification
- PEM format key export for jwt.io compatibility
- Base64 key import/export

## Installation

Add the following dependencies to your `pom.xml`:

```xml
<dependencies>
    <dependency>
        <groupId>io.jsonwebtoken</groupId>
        <artifactId>jjwt-api</artifactId>
        <version>0.11.5</version>
    </dependency>
    <dependency>
        <groupId>io.jsonwebtoken</groupId>
        <artifactId>jjwt-impl</artifactId>
        <version>0.11.5</version>
        <scope>runtime</scope>
    </dependency>
    <dependency>
        <groupId>io.jsonwebtoken</groupId>
        <artifactId>jjwt-jackson</artifactId>
        <version>0.11.5</version>
        <scope>runtime</scope>
    </dependency>
</dependencies>
```

## Usage

### Basic Usage

```java
// Initialize with auto-generated RS256 key pair
JwtUtils jwtUtils = new JwtUtils(3600000); // 1 hour validity

// Generate a token
String token = jwtUtils.generateToken("user123");

// Validate a token
boolean isValid = jwtUtils.validateToken(token);

// Get subject from token
String subject = jwtUtils.getSubject(token);
```

### Using Custom Claims

```java
Map<String, Object> claims = new HashMap<>();
claims.put("role", "ADMIN");
claims.put("email", "user@example.com");

String token = jwtUtils.generateToken("user123", claims);
```

### Using Your Own Key Pair

```java
// Create from Base64-encoded keys
String base64PrivateKey = "..."; // Your Base64-encoded private key
String base64PublicKey = "...";  // Your Base64-encoded public key
JwtUtils jwtUtils = JwtUtils.fromBase64Keys(base64PrivateKey, base64PublicKey, 3600000);

// Or create from PrivateKey and PublicKey objects
JwtUtils jwtUtils = new JwtUtils(privateKey, publicKey, 3600000);
```

### Verifying Tokens on jwt.io

To verify your tokens on [jwt.io](https://jwt.io):

1. Generate a token using JwtUtils
2. Get the PEM format public key:
```java
String pemPublicKey = jwtUtils.getPublicKeyPEM();
```
3. Go to [jwt.io](https://jwt.io)
4. Paste your token in the encoded field
5. In the "Verify Signature" section:
   - Select RS256 algorithm
   - Paste the PEM format public key

## Security Notes

- Keep your private key secure and never expose it
- Use environment variables or secure configuration management for storing keys
- Consider key rotation policies for production environments
- Always validate tokens before trusting their contents

## Contributing

Feel free to open issues or submit pull requests for improvements.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
