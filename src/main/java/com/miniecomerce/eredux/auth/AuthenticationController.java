package com.miniecomerce.eredux.auth;

import com.miniecomerce.eredux.auth.requests.AuthenticationRequest;
import com.miniecomerce.eredux.auth.requests.RegisterRequest;
import com.miniecomerce.eredux.auth.responses.AuthenticationResponse;
import com.miniecomerce.eredux.auth.responses.RegisterResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

import java.io.IOException;

@Controller
@RequiredArgsConstructor
@RequestMapping("/api/v1/auth")
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    @PostMapping("/register")
    public ResponseEntity<RegisterResponse> register(@RequestBody RegisterRequest request, HttpServletResponse response) {
        // Je rentre dans la route register !
        System.out.println("-- Je rentre dans la route register !");
        ResponseEntity<RegisterResponse> registerResponse = authenticationService.register(request, response);
        // Je sors de la route register !
        System.out.println("-- Je sors de la route register !");
        return ResponseEntity.status(HttpStatus.OK).body(registerResponse.getBody());
    }

    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponse> authenticate(@RequestBody AuthenticationRequest request, HttpServletResponse response) {
        // Je rentre dans la route login !
        System.out.println("-- Je rentre dans la route login !");
        AuthenticationResponse authenticationResponse = authenticationService.authenticate(request, response);
        // Je sors de la route login !
        System.out.println("-- Je sors de la route login !");
        return ResponseEntity.status(HttpStatus.OK).body(authenticationResponse);
    }


    @PostMapping("/refresh")
    public void refreshToken( HttpServletRequest request, HttpServletResponse response) throws IOException {
        // Je rentre dans la route login !
        System.out.println("-- Je rentre dans la route login !");
        authenticationService.refreshToken(request, response);
        // Je sors de la route login !
        System.out.println("-- Je sors de la route login !");
    }

}
