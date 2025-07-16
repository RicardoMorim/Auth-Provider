package com.ricardo.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * Main application class for development and testing.
 * This class is excluded from the final JAR distribution.
 */
@SpringBootApplication
@EnableScheduling
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