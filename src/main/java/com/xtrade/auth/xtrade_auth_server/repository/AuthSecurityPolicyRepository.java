package com.xtrade.auth.xtrade_auth_server.repository;

import com.xtrade.auth.xtrade_auth_server.entity.AuthSecurityPolicy;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface AuthSecurityPolicyRepository extends JpaRepository<AuthSecurityPolicy, Long> {

    Optional<AuthSecurityPolicy> findFirstByOrderByIdAsc();
}
