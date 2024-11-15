package com.example.springsecuritybyalibou.token.repository;

import com.example.springsecuritybyalibou.token.Token;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
//we need to save or persist any generated token by our system, so we can add it on authentication service that is called by authentication controller
public interface TokenRepository extends JpaRepository<Token, Long> {

//    List<Token> findAllByUser_IdAndExpiredFalseAndRevokedFalse(Long userId);

    @Query("""
                SELECT  t
                FROM Token t
                INNER JOIN User u ON t.user.id = u.id
                WHERE u.id = :userId AND (t.expired = false OR t.revoked = false) 
            """)
    List<Token> findAllValidTokensByUser(Long userId);


    Optional<Token> findByToken(String token);
    Optional<Token> findByTokenAndExpiredFalseAndRevokedFalse(String token);

}
