package com.example.springsecuritybyalibou.config;


import com.example.springsecuritybyalibou.repository.TokenRepository;
import com.example.springsecuritybyalibou.model.User;
import com.example.springsecuritybyalibou.service.UserService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

//1
//Tell Spring that it will be Managed Bean
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    final JwtService jwtService;
    final UserService userService;
    final TokenRepository tokenRepository;


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        //any issue on spring security start to debug from AuthenticationFilter.doFilterInternal
        //prepare the Bearer token that are sent with request on authorization http header
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        final String token;
        final String username;

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            token = authHeader.substring(7);
            //todo extract the username from Jwt token JwtService;
            try {
                username = jwtService.extractUsername(token);
            } catch (Exception e) {
                logger.error("Hossam :: Invalid JWT Token", e);
                response.setStatus(HttpStatus.UNAUTHORIZED.value());
                return;
            }
            //check if the user is not authenticated yet to continue the JWT validation process
            //if user is already authenticate then we not need to go through the JWT validation Process and passing to SecurityContextHolder directly
            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                //we need to get the user from database
                User user = (User) userService.loadUserByUsername(username);
                //we need to check if the token is valid also on database side
                boolean isTokenValid = tokenRepository.findByToken(token)
                        .map(validToken -> !validToken.isExpired() && !validToken.isRevoked())
                        .orElse(false);
                //next step is to validate and check the token is still valid or not + check also on database side
                if (jwtService.isTokenValid(token, user) && isTokenValid) {
                    // Update Security Context Holder to set Authentication true
                    UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
                    //I want to give some more details about the http request
                    authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    //final step is to update the security context holder
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                }
            }
        }
        //don't forget always to pass to next filter to be executed
        filterChain.doFilter(request, response);

    }
}
