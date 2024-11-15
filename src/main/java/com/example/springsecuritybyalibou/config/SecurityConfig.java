package com.example.springsecuritybyalibou.config;

import com.example.springsecuritybyalibou.user.enums.Permission;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
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

    final LogoutService logoutService;


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
                //more extra configuration that tell spring I want to do log out handler
                //there are (2 Beans) , (2 Implementations) , (2 Methods)
                .logout(logout -> {
                    //logout handler it is waiting for LogoutHandler object
                    //we need to implement all the logout mechanism we didn't specify the logout url yet
                    //spring by default have predefined url for logout, and you can customize it like you want
                    //through the ".logoutUrl"
                    logout.logoutUrl("/api/v1/auth/logout");// on PostMapping
                    //so we tell spring that every time you get request for this specific url just execute this logout handler
                    //from logout service
                    logout.addLogoutHandler(logoutService);
                    //once you have logout success
                    //we want to clear our SecurityContextHolder
                    //so the user that log out cannot access on the resources (apis) again until login again to be added on SecurityContextHolder
                    logout.logoutSuccessHandler((request, response, authentication) -> SecurityContextHolder.clearContext());
                })
                .build();
    }
}
