package com.miniecomerce.eredux.customer;

import com.miniecomerce.eredux.customer.exceptions.RegistrationException;
import com.miniecomerce.eredux.customer.exceptions.InvalidLoginException;
import com.miniecomerce.eredux.customer.exceptions.AuthenticationException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Date;

@RestController
@RequestMapping("/api/v1")
public class CustomerController {
    private final CustomerService customerService;
    public CustomerController(CustomerService customerService) {
        this.customerService = customerService;
    }

    @PostMapping("/register")
    public ResponseEntity<String> registerUser(@RequestBody RegistrationRequest registrationRequest) {
        try {
            customerService.registerCustomer(registrationRequest);
            return ResponseEntity.ok("User registered successfully");
        } catch (RegistrationException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage());
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest) {
        try {
            // Validate login credentials
            Customer customer = customerService.login(loginRequest.getEmail(), loginRequest.getPassword());

            // Generate JWT token
            String token = generateJwtToken(customer.getId());

            // Create LoginResponse object
            LoginResponse response = new LoginResponse(token);

            return ResponseEntity.ok(response);
        } catch (AuthenticationException e) {
            // Handle authentication exception
            throw new InvalidLoginException("Invalid email or password");
        }
    }

    private String generateJwtToken(Long customerId) {
        // Set the expiration time for the token (e.g., 1 hour)
        long expirationTime = System.currentTimeMillis() + (60 * 60 * 1000);

        // Generate a secret key for signing the token
        byte[] signingKey = Keys.secretKeyFor(SignatureAlgorithm.HS256).getEncoded();

        // Build the JWT token
        return Jwts.builder()
                .setSubject(String.valueOf(customerId))
                .setExpiration(new Date(expirationTime))
                .signWith(Keys.hmacShaKeyFor(signingKey), SignatureAlgorithm.HS256)
                .compact();
    }

}
