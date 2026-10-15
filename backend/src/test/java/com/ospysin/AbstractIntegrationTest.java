package com.ospysin;

import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public abstract class AbstractIntegrationTest {

    protected static final PostgreSQLContainer<?> postgres;

    static {
        postgres = new PostgreSQLContainer<>("postgres:16-alpine")
                .withDatabaseName("ospysin")
                .withUsername("ospysin_admin")
                .withPassword("admin_secret");
        postgres.start();

        // Pre-create unprivileged runtime role so Flyway migration V1 applies its grant/revoke block
        try (var conn = postgres.createConnection("")) {
            try (var stmt = conn.createStatement()) {
                stmt.execute("""
                        DO $$
                        BEGIN
                            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ospysin_app') THEN
                                CREATE ROLE ospysin_app WITH LOGIN PASSWORD 'app_secret_test';
                            END IF;
                        END
                        $$;
                        """);
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to pre-create ospysin_app role in PostgreSQL container", e);
        }
    }

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
        registry.add("spring.flyway.url", postgres::getJdbcUrl);
        registry.add("spring.flyway.user", postgres::getUsername);
        registry.add("spring.flyway.password", postgres::getPassword);
        registry.add("ospysin.execution.watchdog-interval-ms", () -> "3600000");
    }
}
