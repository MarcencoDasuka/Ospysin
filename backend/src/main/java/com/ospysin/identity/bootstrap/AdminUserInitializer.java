package com.ospysin.identity.bootstrap;

import com.ospysin.identity.User;
import com.ospysin.identity.UserRepository;
import com.ospysin.identity.UserRole;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;

@Slf4j
@Component
@RequiredArgsConstructor
public class AdminUserInitializer implements ApplicationRunner {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final Clock clock;

    @Value("${ADMIN_INITIAL_PASSWORD:${admin.initial-password:admin}}")
    private String initialPassword;

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        if (userRepository.count() == 0) {
            log.info("Users table is empty. Bootstrapping default administrative operator 'admin'...");
            User admin = User.builder()
                    .username("admin")
                    .passwordHash(passwordEncoder.encode(initialPassword))
                    .role(UserRole.ADMIN)
                    .createdAt(Instant.now(clock))
                    .build();
            userRepository.save(admin);
            log.info("Default operator 'admin' initialized successfully.");
        }
    }
}
