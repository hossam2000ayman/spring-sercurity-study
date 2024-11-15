package com.example.springsecuritybyalibou;

import com.example.springsecuritybyalibou.auth.dto.RegisterRequest;
import com.example.springsecuritybyalibou.auth.service.AuthenticationService;
import com.example.springsecuritybyalibou.user.enums.Role;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class SpringSecurityByAlibouApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityByAlibouApplication.class, args);
    }

    @Bean
    public CommandLineRunner commandLineRunner(AuthenticationService service){
        return args -> {
            RegisterRequest admin = RegisterRequest.builder()
                    .firstName("HOSSAM")
                    .lastName("AYMAN")
                    .username("hossam_ayman")
                    .email("admin@gmail.com")
                    .password("password")
                    .role(Role.ADMIN)
                    .build();
            System.out.println("ADMIN Token : "+ service.register(admin).getToken());



            RegisterRequest manager = RegisterRequest.builder()
                    .firstName("MAYSARA")
                    .lastName("SOLEIMANI")
                    .username("maysara_solaiman")
                    .email("msolayman@gmail.com")
                    .password("password")
                    .role(Role.MANAGER)
                    .build();
            System.out.println("Manager Token : "+ service.register(manager).getToken());
        };
    }

}
