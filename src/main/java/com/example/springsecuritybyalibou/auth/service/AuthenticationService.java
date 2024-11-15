package com.example.springsecuritybyalibou.auth.service;

import com.example.springsecuritybyalibou.auth.dto.AuthenticationRequest;
import com.example.springsecuritybyalibou.auth.dto.RegisterRequest;
import com.example.springsecuritybyalibou.auth.dto.response.AuthenticationResponse;
import com.example.springsecuritybyalibou.config.JwtService;
import com.example.springsecuritybyalibou.user.User;
import com.example.springsecuritybyalibou.user.UserRepository;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    final UserRepository userRepository;
    final PasswordEncoder passwordEncoder;
    final JwtService jwtService;
    final AuthenticationManager authenticationManager;

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
        String token = jwtService.generateToken(user);
        return new AuthenticationResponse(token);
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
        return new AuthenticationResponse(token);
    }
}
