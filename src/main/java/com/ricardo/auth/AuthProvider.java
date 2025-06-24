package com.ricardo.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Main application class for development and testing.
 * This class is excluded from the final JAR distribution.
 */
@SpringBootApplication
public class AuthProvider {

    /**
     * The entry point of application.
     *
     * @param args the input arguments
     */
    public static void main(String[] args) {
        SpringApplication.run(AuthProvider.class, args);
    }
}