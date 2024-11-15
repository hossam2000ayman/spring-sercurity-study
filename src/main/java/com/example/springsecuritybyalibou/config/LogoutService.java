package com.example.springsecuritybyalibou.config;

import com.example.springsecuritybyalibou.model.Token;
import com.example.springsecuritybyalibou.repository.TokenRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class LogoutService implements LogoutHandler {

    final TokenRepository tokenRepository;

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {

        //1- we want to invalidate the token, so we need to extract the token from request right there
        //2- we need to fetch this request in database and invalidated
        //3- then the JwtAuthenticationFilter will do the job since we update our mechanism or our implementation there

        final String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        final String jwt;

        if (header != null && header.startsWith("Bearer ")) {
            jwt = header.substring(7);
            Token token = tokenRepository.findByTokenAndExpiredFalseAndRevokedFalse(jwt).orElseThrow(()-> new RuntimeException("Token is not found or expired or revoked"));
            if (token != null) {
                token.setExpired(true);
                token.setRevoked(true);
                tokenRepository.save(token);
            }
        }

    }
}
