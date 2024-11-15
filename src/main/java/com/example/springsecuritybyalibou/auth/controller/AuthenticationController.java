package com.example.springsecuritybyalibou.auth.controller;

import com.example.springsecuritybyalibou.auth.dto.AuthenticationRequest;
import com.example.springsecuritybyalibou.auth.dto.RegisterRequest;
import com.example.springsecuritybyalibou.auth.dto.response.AuthenticationResponse;
import com.example.springsecuritybyalibou.auth.service.AuthenticationService;
import lombok.*;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    final AuthenticationService authenticationService;

    @Getter
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Request<T> {
        T data;
    }




    @PostMapping(value = "/register",produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<AuthenticationResponse> register(@RequestBody Request<RegisterRequest> request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(authenticationService.register(request.getData()));
    }

    @PostMapping("authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(@RequestBody Request<AuthenticationRequest> request) {
        return ResponseEntity.ok(authenticationService.authenticate(request.getData()));
    }

}
