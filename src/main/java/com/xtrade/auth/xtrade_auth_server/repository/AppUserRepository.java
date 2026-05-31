package com.xtrade.auth.xtrade_auth_server.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.xtrade.auth.xtrade_auth_server.entity.AppUser;

import java.util.Optional;

public interface AppUserRepository extends JpaRepository<AppUser, Long> {

    Optional<AppUser> findByUsernameIgnoreCase(String username);

    boolean existsByUsernameIgnoreCase(String username);

    boolean existsByDocumentNumber(String documentNumber);

    boolean existsByEmailIgnoreCase(String email);
}