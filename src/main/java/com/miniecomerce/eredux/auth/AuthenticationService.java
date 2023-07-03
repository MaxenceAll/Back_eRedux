package com.miniecomerce.eredux.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.miniecomerce.eredux.config.JwtService;
import com.miniecomerce.eredux.customer.Customer;
import com.miniecomerce.eredux.customer.CustomerRepository;
import com.miniecomerce.eredux.customer.Role;
import com.miniecomerce.eredux.token.Token;
import com.miniecomerce.eredux.token.TokenRepository;
import com.miniecomerce.eredux.token.TokenType;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import java.io.IOException;


@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final CustomerRepository customerRepository;
    private final TokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public ResponseEntity<?> register(RegisterRequest request, HttpServletResponse response) {
        var existingCustomer = customerRepository.findByEmail(request.getEmail());
        if (existingCustomer.isPresent()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(AuthenticationErrorResponse.builder()
                            .error(HttpStatus.BAD_REQUEST.value())
                            .message("Email already exists")
                            .result(false)
                            .build());
        }

        var customer = Customer.builder()
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();
        var savedCustomer = customerRepository.save(customer);
        var jwtToken = jwtService.generateToken(savedCustomer);

        var refreshToken = jwtService.generateToken(savedCustomer);
        saveCustomerTokenToDb(savedCustomer, jwtToken);

        // Set the refresh token as an HTTP-only cookie
        Cookie refreshCookie = new Cookie("refreshToken", refreshToken);
        refreshCookie.setHttpOnly(true);
        refreshCookie.setPath("/");
        response.addCookie(refreshCookie);

        return ResponseEntity.status(HttpStatus.OK)
                .body(AuthenticationResponse.builder()
                        .accessToken(jwtToken)
                        .message("Registration successful")
                        .result(true)
                        .build());
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword())
        );

        var customer = customerRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new RuntimeException("Customer not found"));

        var jwtToken = jwtService.generateToken(customer);
        var refreshToken = jwtService.generateRefreshToken(customer);
        revokeCustomerToken(customer);
        saveCustomerTokenToDb(customer, jwtToken);
        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .build();
    }

    private void revokeCustomerToken(Customer customer) {
        var validCustomerToken = tokenRepository.findAllValidTokenByCustomer(customer.getId());
        if (validCustomerToken.isEmpty()) return;
        validCustomerToken.forEach(token -> {
            token.setExpired(true);
            token.setRevoked(true);
        });
        tokenRepository.saveAll(validCustomerToken);
    }

    private void saveCustomerTokenToDb(Customer customer, String jwtToken) {
        var token = Token.builder()
                .customer(customer)
                .token(jwtToken)
                .tokenType(TokenType.ACCESS)
                .isRevoked(false)
                .isExpired(false)
                .build();
        tokenRepository.save(token);
    }

    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        final String refreshToken;
        final String customerEmail;
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return;
        } else {
            refreshToken = authHeader.substring(7);
            customerEmail = jwtService.extractCustomerEmail(refreshToken);
            if (customerEmail != null) {
                var user = this.customerRepository.findByEmail(customerEmail).orElseThrow();
                //    Ici intégrer la vérification de la validité du refreshToken
                if (jwtService.isTokenValid(refreshToken, user)) {
                    var newAccessToken = jwtService.generateToken(user);
                    revokeCustomerToken(user);
                    saveCustomerTokenToDb(user, newAccessToken);
                    var authResponse = AuthenticationResponse.builder()
                            .accessToken(newAccessToken)
                            .build();
                    new ObjectMapper().writeValue(response.getOutputStream(), authResponse);
                }
            }
        }
    }
}
