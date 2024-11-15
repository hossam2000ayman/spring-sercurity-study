package com.example.springsecuritybyalibou.auth.dto;

import com.example.springsecuritybyalibou.user.enums.Role;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
@Builder
public class RegisterRequest {
    String firstName;
    String lastName;
    String email;
    String username;
    String password;
    Role role;
}
