package com.example.springsecuritybyalibou.token;

import com.example.springsecuritybyalibou.token.enums.TokenType;
import com.example.springsecuritybyalibou.user.User;
import com.fasterxml.jackson.annotation.JsonBackReference;
import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "tokens")
@NoArgsConstructor
@AllArgsConstructor
@Setter
@Getter
@Builder
public class Token {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    Long id;
    String token;
    @Enumerated(EnumType.STRING)
    TokenType tokenType;
    boolean expired;
    boolean revoked;

    @ManyToOne
    @JoinColumn(name = "user_id")
    @JsonBackReference(value = "user_tokens")
    User user;
}
