package com.proofvault;

import com.zaxxer.hikari.HikariDataSource;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

import javax.sql.DataSource;
import java.sql.Connection;

/**
 * Resilient DataSource configuration:
 * Connects to primary MySQL database if available and valid.
 * Automatically falls back to an embedded in-memory database (H2 in MySQL compatibility mode)
 * if MySQL is unreachable, missing, or has placeholder configuration on cloud hosts.
 */
@Configuration
public class DataSourceConfig {

    @Value("${spring.datasource.url:}")
    private String primaryUrl;

    @Value("${spring.datasource.username:}")
    private String primaryUsername;

    @Value("${spring.datasource.password:}")
    private String primaryPassword;

    @Value("${spring.datasource.driver-class-name:com.mysql.cj.jdbc.Driver}")
    private String primaryDriver;

    @Bean
    @Primary
    public DataSource dataSource() {
        boolean isBrokenPlaceholder = primaryUrl == null ||
                primaryUrl.isBlank() ||
                primaryUrl.contains("<paste") ||
                primaryUrl.contains("://:/") ||
                primaryUrl.contains("${{");

        if (!isBrokenPlaceholder) {
            try {
                System.out.println("Attempting connection to primary MySQL database: " + primaryUrl);
                HikariDataSource ds = new HikariDataSource();
                ds.setJdbcUrl(primaryUrl);
                ds.setUsername(primaryUsername != null ? primaryUsername : "root");
                ds.setPassword(primaryPassword != null ? primaryPassword : "");
                ds.setDriverClassName(primaryDriver);
                ds.setConnectionTimeout(4000); // 4-second fail-fast timeout
                ds.setMaximumPoolSize(5);

                // Probe connection
                try (Connection conn = ds.getConnection()) {
                    System.out.println("Successfully connected to primary MySQL database: " + conn.getMetaData().getDatabaseProductName());
                    return ds;
                }
            } catch (Exception e) {
                System.err.println("Notice: Primary MySQL database unreachable (" + e.getMessage() + "). Activating embedded database fallback.");
            }
        } else {
            System.err.println("Notice: Primary database configuration is unpopulated. Activating embedded database fallback.");
        }

        // Resilient in-memory database fallback (H2 with MySQL syntax compatibility)
        HikariDataSource fallback = new HikariDataSource();
        fallback.setJdbcUrl("jdbc:h2:mem:proofvault_db;MODE=MySQL;DATABASE_TO_LOWER=TRUE;DEFAULT_NULL_ORDER=HIGH;DB_CLOSE_DELAY=-1");
        fallback.setDriverClassName("org.h2.Driver");
        fallback.setUsername("sa");
        fallback.setPassword("");
        fallback.setMaximumPoolSize(5);
        System.out.println("ProofVault resilient database active (H2 in MySQL mode). All operations ready.");
        return fallback;
    }
}
