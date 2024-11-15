package com.example.springsecuritybyalibou.service;

import com.example.springsecuritybyalibou.dto.AuthenticationRequest;
import com.example.springsecuritybyalibou.dto.RegisterRequest;
import com.example.springsecuritybyalibou.dto.response.AuthenticationResponse;
import com.example.springsecuritybyalibou.config.JwtService;
import com.example.springsecuritybyalibou.model.Token;
import com.example.springsecuritybyalibou.model.enums.TokenType;
import com.example.springsecuritybyalibou.repository.TokenRepository;
import com.example.springsecuritybyalibou.model.User;
import com.example.springsecuritybyalibou.repository.UserRepository;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    final UserRepository userRepository;
    final PasswordEncoder passwordEncoder;
    final JwtService jwtService;
    final AuthenticationManager authenticationManager;
    // we need to save or persist any generated token by our system,
// so we can add it on authentication service that is called by authentication controller
    final TokenRepository tokenRepository;

    public AuthenticationResponse register(RegisterRequest registerRequest) {
        User user = User.builder()
                .firstName(registerRequest.getFirstName())
                .lastName(registerRequest.getLastName())
                .email(registerRequest.getEmail())
                .username(registerRequest.getUsername())
                .password(passwordEncoder.encode(registerRequest.getPassword()))
                .role(registerRequest.getRole())
                .build();
        userRepository.save(user);
        String jwt = jwtService.generateToken(user);
        revokeAllUserTokens(user);
        saveUserToken(user, jwt);
        return new AuthenticationResponse(jwt);
    }

    public AuthenticationResponse authenticate(AuthenticationRequest authenticationRequest) {
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authenticationRequest.getUsername(), authenticationRequest.getPassword()));
        } catch (Exception e) {
            e.printStackTrace();
        }
        //if it passes through this logic mean that the user is authenticated otherwise it will throw exception,
        //so I wil just need to generate the token and then send it back
        User user = userRepository.findByUsername(authenticationRequest.getUsername()).orElseThrow(() -> new EntityNotFoundException("user not found"));
        String token = jwtService.generateToken(user);
        revokeAllUserTokens(user);
        saveUserToken(user, token);
        return new AuthenticationResponse(token);
    }

    private void saveUserToken(User user, String jwt) {
        Token token = Token.builder()
                .user(user)
                .token(jwt)
                .tokenType(TokenType.BEARER_TOKEN)
                .revoked(false)
                .expired(false)
                .build();

        tokenRepository.saveAndFlush(token);
    }

    private void revokeAllUserTokens(User user) {
        //I want to fetch all the valid tokens for specific user into database
        List<Token> validUserTokens = tokenRepository.findAllValidTokensByUser(user.getId());
        //then revoke these token that are being found
        if (!validUserTokens.isEmpty()) {
            validUserTokens.forEach((token) -> {
                token.setExpired(true);
                token.setRevoked(true);
            });
            tokenRepository.saveAll(validUserTokens);
        }
    }
}
