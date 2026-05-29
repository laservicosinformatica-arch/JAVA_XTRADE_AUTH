package com.xtrade.auth.xtrade_auth_server.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.xtrade.auth.xtrade_auth_server.entity.AppRole;

import java.util.Optional;

public interface AppRoleRepository extends JpaRepository<AppRole, Long> {

    Optional<AppRole> findByName(String name);
}