package com.example.springsecuritybyalibou.config;

import com.example.springsecuritybyalibou.user.enums.Permission;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import static com.example.springsecuritybyalibou.user.enums.Role.ADMIN;
import static com.example.springsecuritybyalibou.user.enums.Role.MANAGER;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@EnableMethodSecurity //this is used to execute @PreAuthorize(...) ,  boolean prePostEnabled() default true;
//if spring version is older than 3.0 , @EnableGlobalMethodSecurity(prePostEnabled = PreAuthorized)
public class SecurityConfig {
    final JwtAuthenticationFilter jwtAuthenticationFilter;
    final AuthenticationProvider authenticationProvider;


    //At the application startup spring security will try to look for bean of type SecurityFilterChain
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        //do the configuration
        return httpSecurity
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(
                        authorize -> authorize
                                .requestMatchers("api/v1/auth/**").permitAll()

                                .requestMatchers("api/v1/management").hasAnyRole(ADMIN.name(), MANAGER.name())
                                .requestMatchers(HttpMethod.GET, "api/v1/management").hasAnyAuthority(Permission.ADMIN_READ.name(), Permission.MANAGER_READ.name())
                                .requestMatchers(HttpMethod.POST, "api/v1/management").hasAnyAuthority(Permission.ADMIN_CREATE.name(), Permission.MANAGER_CREATE.name())
                                .requestMatchers(HttpMethod.PUT, "api/v1/management").hasAnyAuthority(Permission.ADMIN_UPDATE.name(), Permission.MANAGER_UPDATE.name())
                                .requestMatchers(HttpMethod.DELETE, "api/v1/management").hasAnyAuthority(Permission.ADMIN_DELETE.name(), Permission.MANAGER_DELETE.name())


//                                .requestMatchers("api/v1/admin").hasRole(ADMIN.name())
//                                .requestMatchers(HttpMethod.GET, "api/v1/admin").hasAuthority(Permission.ADMIN_READ.name())
//                                .requestMatchers(HttpMethod.POST, "api/v1/admin").hasAuthority(Permission.ADMIN_CREATE.name())
//                                .requestMatchers(HttpMethod.PUT, "api/v1/admin").hasAuthority(Permission.ADMIN_UPDATE.name())
//                                .requestMatchers(HttpMethod.DELETE, "api/v1/admin").hasAuthority(Permission.ADMIN_DELETE.name())

                                .anyRequest().authenticated()
                )
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authenticationProvider(authenticationProvider)
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }
}