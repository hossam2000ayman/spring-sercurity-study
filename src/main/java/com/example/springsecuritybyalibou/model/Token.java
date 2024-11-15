package com.example.springsecuritybyalibou.model;

import com.example.springsecuritybyalibou.model.enums.TokenType;
import com.example.springsecuritybyalibou.model.User;
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
