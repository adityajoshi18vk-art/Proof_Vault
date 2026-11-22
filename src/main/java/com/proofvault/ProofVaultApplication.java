package com.proofvault;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Main entry point for the ProofVault application.
 * MySQL DataSource is now active and connected via JDBC.
 */
@SpringBootApplication
public class ProofVaultApplication {

    public static void main(String[] args) {
        SpringApplication.run(ProofVaultApplication.class, args);
    }
}
