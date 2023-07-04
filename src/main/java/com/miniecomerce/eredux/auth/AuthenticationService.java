package com.miniecomerce.eredux.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.miniecomerce.eredux.auth.requests.AuthenticationRequest;
import com.miniecomerce.eredux.auth.requests.RegisterRequest;
import com.miniecomerce.eredux.auth.responses.AuthenticationResponse;
import com.miniecomerce.eredux.auth.responses.RegisterResponse;
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
import org.springframework.security.core.userdetails.UsernameNotFoundException;
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

    public ResponseEntity<RegisterResponse> register(RegisterRequest request, HttpServletResponse response) {

        // Je check s'il existe un customer avec le même email
        System.out.println("-- Je check s'il existe un customer avec le même email");
        if (customerRepository.existsByEmail(request.getEmail())) {
            // If the email already exists, return an error response
            return ResponseEntity.badRequest()
                    .body(RegisterResponse.builder()
                            .error(HttpStatus.BAD_REQUEST.value())
                            .message("Email already exists")
                            .result(false)
                            .build());
        }

        // Si non, je crée un nouveau customer via builder
        System.out.println("-- Si non, je crée un nouveau customer via builder");
        var customer = Customer.builder()
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();

        // Je sauvegarde le customer dans la DB
        System.out.println("-- Je sauvegarde le customer dans la DB");
        var savedCustomer = customerRepository.save(customer);

        // Je génère un token et un refresh token
        System.out.println("-- Je génère un token et un refresh token");
        var jwtToken = jwtService.generateToken(savedCustomer);
        var refreshToken = jwtService.generateRefreshToken(savedCustomer);

        // Les 2 tokens sont créés !
        System.out.println("-- Les 2 tokens sont créés !");
        // Je sauvegarde le token et le refresh token dans la DB
        System.out.println("-- Je sauvegarde le token et le refresh token dans la DB");
        saveCustomerTokenToDb(savedCustomer, refreshToken);

        // Création du cookie pour le refresh token
        System.out.println("-- Création du cookie pour le refresh token");
        Cookie refreshCookie = new Cookie("refreshToken", refreshToken);
        // httpOnly = true pour empêcher le JS d'accéder au cookie
        refreshCookie.setHttpOnly(true);
        // TODO voir si possible de le mettre en secure en dév (httpS)
        refreshCookie.setPath("/");
        // Ajout du cookie à la réponse
        System.out.println("-- Ajout du cookie à la réponse");
        response.addCookie(refreshCookie);

        // Je log le nouvel utilisateur dans spring boot security
        System.out.println("-- Je log le nouvel utilisateur dans spring boot security");
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword())
        );

        // Je retourne une réponse avec le token et le refresh token en cookie
        System.out.println("-- Je retourne une réponse avec le token et le refresh token en cookie");
        return ResponseEntity.status(HttpStatus.OK)
                .body(RegisterResponse.builder()
                        .accessToken(jwtToken)
                        .message("Registration successful")
                        .email(customer.getEmail())
                        .result(true)
                        .build());
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request, HttpServletResponse response) {

        // Je log lutilisateur dans spring boot security
        System.out.println("-- Je log lutilisateur dans spring boot security");
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword())
        );

        // Je récupère le customer
        System.out.println("-- Je récupère le customer");
        var customer = customerRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new UsernameNotFoundException("Customer not found"));

        // Je génère un token et un refresh token
        System.out.println("-- Je génère un token et un refresh token");
        var jwtToken = jwtService.generateToken(customer);
        var refreshToken = jwtService.generateRefreshToken(customer);

        // Je sauvegarde le token et le refresh token dans la DB
        System.out.println("-- Je sauvegarde le token et le refresh token dans la DB");
        revokeCustomerToken(customer);
        saveCustomerTokenToDb(customer, refreshToken);

        // Création du cookie pour le refresh token
        System.out.println("-- Création du cookie pour le refresh token");
        Cookie refreshCookie = new Cookie("refreshToken", refreshToken);
        refreshCookie.setHttpOnly(true);
        refreshCookie.setPath("/");
        // Ajout du cookie à la réponse
        System.out.println("-- Ajout du cookie à la réponse");
        response.addCookie(refreshCookie);

        // Je retourne une réponse avec le token et le refresh token en cookie
        System.out.println("-- Je retourne une réponse avec le token et le refresh token en cookie");
        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .result(true)
                .message("Login successful")
                .email(customer.getEmail())
                .build();
    }

    private void revokeCustomerToken(Customer customer) {
        // Je récupère tous les tokens valides du customer
        System.out.println("-- Je récupère tous les tokens valides du customer");
        var validCustomerToken = tokenRepository.findAllValidTokenByCustomer(customer.getId());
        // Si aucun token valide, je ne fais rien
        System.out.println("-- Si aucun token valide, je ne fais rien");
        if (validCustomerToken.isEmpty()) return;
        // Sinon, je les révoque tous
        System.out.println("-- Sinon, je les révoque tous");
        validCustomerToken.forEach(token -> {
            token.setExpired(true);
            token.setRevoked(true);
        });
        // Je sauvegarde les tokens révoqués dans la DB
        System.out.println("-- Je sauvegarde les tokens révoqués dans la DB");
        tokenRepository.saveAll(validCustomerToken);
    }

    private void saveCustomerTokenToDb(Customer customer, String jwtToken) {

        // Je crée un nouveau token via builder
        System.out.println("-- Je crée un nouveau token via builder");
        var token = Token.builder()
                .customer(customer)
                .token(jwtToken)
                .tokenType(TokenType.REFRESH)
                .isRevoked(false)
                .isExpired(false)
                .build();
        // Je sauvegarde le token dans la DB
        System.out.println("-- Je sauvegarde le token dans la DB");
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
