package com.miniecomerce.eredux.token;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface TokenRepository extends JpaRepository<Token, Integer> {

    @Query("select t from Token t inner join Customer c on t.customer.id = c.id where c.id = :userId and (t.isExpired = false or t.isRevoked = false)")
    List<Token> findAllValidTokenByCustomer(Long userId);

    Optional<Token> findByToken(String token);

}
