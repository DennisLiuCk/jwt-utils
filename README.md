# JWT Utils

A Java utility library for handling JWT (JSON Web Token) operations. This library provides a simple and secure way to generate, validate, and parse JWT tokens.

## Features

- Generate JWT tokens with custom claims
- Validate JWT tokens
- Extract claims from tokens
- Built-in support for subject and expiration claims
- Secure key generation using HMAC-SHA256

## Requirements

- Java 11 or higher
- Maven

## Installation

Add the following dependencies to your `pom.xml`:

```xml
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
```

## Usage

### Basic Token Generation

```java
// Initialize JwtUtils with a secret key and token validity duration
JwtUtils jwtUtils = new JwtUtils("your-256-bit-secret", 3600000); // 1 hour validity

// Generate a token
String token = jwtUtils.generateToken("userId123");

// Validate token
boolean isValid = jwtUtils.validateToken(token);

// Get subject from token
String subject = jwtUtils.getSubject(token);
```

### Token with Custom Claims

```java
Map<String, Object> claims = new HashMap<>();
claims.put("role", "ADMIN");
claims.put("email", "user@example.com");

String token = jwtUtils.generateToken("userId123", claims);

// Later, extract claims
Claims allClaims = jwtUtils.getAllClaims(token);
String role = allClaims.get("role", String.class);
```

## Security Considerations

1. Use a strong secret key (at least 256 bits)
2. Keep your secret key secure and never expose it
3. Set appropriate token expiration times
4. Validate tokens before trusting their contents

## Contributing

Feel free to submit issues and enhancement requests!
