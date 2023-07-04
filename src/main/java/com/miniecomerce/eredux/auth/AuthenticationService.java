package com.miniecomerce.eredux.auth;

import com.miniecomerce.eredux.auth.requests.AuthenticationRequest;
import com.miniecomerce.eredux.auth.requests.RegisterRequest;
import com.miniecomerce.eredux.auth.responses.AuthenticationResponse;
import com.miniecomerce.eredux.auth.responses.RefreshResponse;
import com.miniecomerce.eredux.auth.responses.RegisterResponse;
import com.miniecomerce.eredux.config.JwtService;
import com.miniecomerce.eredux.customer.Customer;
import com.miniecomerce.eredux.customer.CustomerRepository;
import com.miniecomerce.eredux.customer.Role;
import com.miniecomerce.eredux.token.Token;
import com.miniecomerce.eredux.token.TokenRepository;
import com.miniecomerce.eredux.token.TokenType;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;

import java.io.IOException;
import java.util.List;


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

    private void saveCustomerTokenToDb(Customer customer, String refreshToken) {

        // Je crée un nouveau token via builder
        System.out.println("-- Je crée un nouveau token via builder");
        var token = Token.builder()
                .customer(customer)
                .token(refreshToken)
                .tokenType(TokenType.REFRESH)
                .isRevoked(false)
                .isExpired(false)
                .build();
        // Je sauvegarde le token dans la DB
        System.out.println("-- Je sauvegarde le token dans la DB");
        tokenRepository.save(token);
    }

    public ResponseEntity<RefreshResponse> refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {

        // Je rentre dans la méthode refreshToken
        System.out.println("-- Je rentre dans la méthode refreshToken");
        // Extract the refresh token from the cookie
        System.out.println("-- Extract the refresh token from the cookie");
        Cookie[] cookies = request.getCookies();
        String refreshToken = null;
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals("refreshToken")) {
                    refreshToken = cookie.getValue();
                    break;
                }
            }
        }
        System.out.println("-- Voilà le refresh token : " + refreshToken);
        if (refreshToken == null) {
            // Si le refresh token est null, je retourne une erreur
            System.out.println("-- Refresh token is missing");
            return ResponseEntity.status(HttpStatus.OK)
                    .body(RefreshResponse.builder()
                    .result(false)
                    .message("Refresh token is missing")
                    .build());
        }

        // J'extrait le customer à partir du refresh token
        System.out.println("-- J'extrait le customer à partir du refresh token");
        var verifEmail = jwtService.extractCustomerEmail(refreshToken);
        System.out.println("-- Voilà l'email extrait du token : " + verifEmail);
        // Je récupère le customer à partir de email extrait du token
        System.out.println("-- Je récupère le customer à partir de email extrait du token");
        var verifCustomer = customerRepository.findByEmail(verifEmail)
                .orElseThrow(() -> new UsernameNotFoundException("Customer not found"));


        // Création d'un objet claims à partir du token
        Claims claims = jwtService.parseToken(refreshToken);
        System.out.println("-- claims extraits du token");
        // Récupération de l'email du customer
        String email = claims.getSubject();
        System.out.println("-- email extrait du token");

        // Je récupère le customer
        System.out.println("-- Je récupère le customer");
        var customer = customerRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("Customer not found"));

        // Je récupère le refresh token dans la DB pour vérifier qu'il est valide
        System.out.println("-- Je récupère le refresh token dans la DB pour vérifier qu'il est valide");
        try {
            // Validate the format and signature of the refresh token
            jwtService.parseToken(refreshToken);
        } catch (JwtException e) {
            // Refresh token is invalid
            System.out.println("-- Refresh token is invalid");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(RefreshResponse.builder()
                            .result(false)
                            .message("Invalid refresh token")
                            .build());
        }

        // Je vérifie que le refresh token est tjs valide dans la db
        System.out.println("-- Je vérifie que le refresh token est tjs valide dans la db");
        // Retrieve the valid tokens for the customer
        List<Token> validTokens = tokenRepository.findAllValidTokenByCustomer(customer.getId());

        // Je dois vérifier que le refresh token est bien dans la liste des tokens valides
        System.out.println("-- Je dois vérifier que le refresh token est bien dans la liste des tokens valides");
        String finalRefreshToken = refreshToken;
        boolean isRefreshTokenValid = validTokens.stream()
                .anyMatch(token -> token.getToken().equals(finalRefreshToken));

        // Si le refresh token n'est pas valide, je retourne une erreur
        System.out.println("-- Si le refresh token n'est pas valide, je retourne une erreur");
        if (!isRefreshTokenValid) {
            // Refresh token is invalid
            System.out.println("-- Refresh token is invalid");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(RefreshResponse.builder()
                            .result(false)
                            .message("Invalid refresh token")
                            .build());
        }

        // Je vérifie que le refresh token appartient bien au customer
        System.out.println("-- Je vérifie que le refresh token appartient bien au customer");
        if (!verifEmail.equals(verifCustomer.getEmail())) {
            // Refresh token does not belong to the correct customer
            System.out.println("-- Refresh token does not belong to the correct customer");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(RefreshResponse.builder()
                            .result(false)
                            .message("Invalid refresh token")
                            .build());
        }

        // Je revoke tous les tokens du customer
        revokeCustomerToken(customer);
        // Je génère un nouveau token et un nouveau refresh token
        System.out.println("-- Je génère un nouveau token et un nouveau refresh token");
        var jwtToken = jwtService.generateToken(customer);
        var newRefreshToken = jwtService.generateRefreshToken(customer);
        // Je sauvegarde le nouveau refresh token dans la DB
        System.out.println("-- Je sauvegarde le nouveau refresh token dans la DB");
        saveCustomerTokenToDb(customer, newRefreshToken);

        // Je crée un nouveau cookie pour le refresh token
        System.out.println("-- Je crée un nouveau cookie pour le refresh token");
        Cookie refreshCookie = new Cookie("refreshToken", newRefreshToken);
        refreshCookie.setHttpOnly(true);
        refreshCookie.setPath("/");
        // Je l'ajoute à la réponse
        System.out.println("-- Je l'ajoute à la réponse");
        response.addCookie(refreshCookie);

        // Je retourne une réponse avec le token et le refresh token en cookie
        System.out.println("-- Je retourne une réponse avec le token et le refresh token en cookie");
        return ResponseEntity.status(HttpStatus.OK)
                .body(RefreshResponse.builder()
                .result(true)
                .message("Refresh token successful")
                .accessToken(jwtToken)
                .build());
    }

    @GetMapping("/auth")
    public ResponseEntity<AuthenticationResponse> checkAuthentication(HttpServletRequest request, HttpServletResponse response) {
        System.out.println("-- Je suis dans la méthode auth");
        // Extraction du token d'authentification
        String token = extractTokenFromRequest(request);
        System.out.println("-- Token trouvé");

        // Si le token est null, l'utilisateur n'est pas authentifié
        if (token == null) {
            // Access token is not present, so the user is not authenticated
            System.out.println("-- Access token is not present, so the user is not authenticated");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        // Si le token est présent, je vérifie sa validité
        try {

            // Création d'un objet claims à partir du token
            Claims claims = jwtService.parseToken(token);
            System.out.println("-- claims extraits du token");
            // Récupération de l'email du customer
            String email = claims.getSubject();
            System.out.println("-- email extrait du token");

            // Je check le customer
            customerRepository.findByEmail(email)
                    .orElseThrow(() -> new UsernameNotFoundException("Customer not found"));
            System.out.println("-- Customer trouvé !");

            // Access token is valid, user is authenticated
            System.out.println("-- Access token is valid, user is authenticated");
            System.out.println("-- Je sors de la méthode auth");
            return ResponseEntity.status(HttpStatus.OK)
                    .body(AuthenticationResponse.builder()
                            .result(true)
                            .message("User is authenticated")
                            .accessToken(token)
                            .email(email)
                            .build());
        } catch (Exception e) {
            System.out.println("-- Exception thrown ");
            System.out.println("-- Je sors de la méthode auth");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(AuthenticationResponse.builder()
                            .result(false)
                            .message("Exception : " + e.getMessage())
                            .build());
        }
    }

    private String extractTokenFromRequest(HttpServletRequest request) {
        System.out.println("-- Je suis dans la méthode extractRefreshTokenFromRequest");
        String token = null;

        // Retrieve the token from the Authorization header
        String authorizationHeader = request.getHeader("Authorization");
        System.out.println("-- authorizationHeader trouvé");

        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            // Extract the access token from the Authorization header
            token = authorizationHeader.substring(7);
            System.out.println("-- token trouvé");
        }
        System.out.println("-- Je sors de la méthode extractRefreshTokenFromRequest");
        return token;
    }


}
