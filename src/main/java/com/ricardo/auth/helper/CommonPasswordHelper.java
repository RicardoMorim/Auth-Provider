package com.ricardo.auth.helper;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Set;
import java.util.stream.Collectors;

public class CommonPasswordHelper {

    public static Set<String> loadCommonPasswords(String resourcePath) {
        return loadCommonPasswords(resourcePath, CommonPasswordHelper.class);
    }

    public static Set<String> loadCommonPasswords(String resourcePath, Class<?> contextClass) {
        // Try different resource loading strategies in order
        return tryLoadFromMultipleSources(resourcePath, contextClass);
    }

    private static Set<String> tryLoadFromMultipleSources(String resourcePath, Class<?> contextClass) {
        // Strategy 1: Try as external file (user's project)
        try {
            Set<String> passwords = loadFromFileSystem(resourcePath);
            if (!passwords.isEmpty()) {
                System.out.println("Loaded common passwords from external file: " + resourcePath);
                return passwords;
            }
        } catch (Exception e) {
            // Continue to next strategy
        }

        // Strategy 2: Try as classpath resource from user's project
        try {
            Set<String> passwords = loadFromClasspath(resourcePath, contextClass);
            if (!passwords.isEmpty()) {
                System.out.println("Loaded common passwords from classpath: " + resourcePath);
                return passwords;
            }
        } catch (Exception e) {
            // Continue to next strategy
        }

        // Strategy 3: Try from starter's built-in resources
        try {
            Set<String> passwords = loadFromStarterClasspath(resourcePath);
            if (!passwords.isEmpty()) {
                System.out.println("Loaded common passwords from starter resources: " + resourcePath);
                return passwords;
            }
        } catch (Exception e) {
            // Continue to fallback
        }

        // Strategy 4: Fallback to hardcoded defaults
        System.out.println("Using default common passwords list");
        return getDefaultCommonPasswords();
    }

    private static Set<String> loadFromFileSystem(String filePath) throws IOException {
        Path path = Paths.get(filePath);
        if (!Files.exists(path)) {
            throw new IOException("File not found: " + filePath);
        }

        return Files.lines(path, StandardCharsets.UTF_8)
                .map(String::trim)
                .filter(line -> !line.isEmpty())
                .filter(line -> !line.startsWith("#"))
                .map(String::toLowerCase)
                .collect(Collectors.toSet());
    }

    private static Set<String> loadFromClasspath(String resourcePath, Class<?> contextClass) throws IOException {
        InputStream inputStream = contextClass.getResourceAsStream(resourcePath);
        if (inputStream == null) {
            throw new IOException("Classpath resource not found: " + resourcePath);
        }

        return readFromInputStream(inputStream);
    }

    private static Set<String> loadFromStarterClasspath(String resourcePath) throws IOException {
        // Always load from starter's resources as fallback
        InputStream inputStream = CommonPasswordHelper.class.getResourceAsStream(resourcePath);
        if (inputStream == null) {
            throw new IOException("Starter resource not found: " + resourcePath);
        }

        return readFromInputStream(inputStream);
    }

    private static Set<String> readFromInputStream(InputStream inputStream) throws IOException {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream, StandardCharsets.UTF_8))) {
            return reader.lines()
                    .map(String::trim)
                    .filter(line -> !line.isEmpty())
                    .filter(line -> !line.startsWith("#"))
                    .map(String::toLowerCase)
                    .collect(Collectors.toSet());
        }
    }

    private static Set<String> getDefaultCommonPasswords() {
        return Set.of(
                "password", "123456", "password123", "admin", "qwerty",
                "letmein", "welcome", "monkey", "1234567890", "abc123"
        );
    }

    public static boolean isCommonPassword(String password, Set<String> commonPasswords) {
        return commonPasswords.contains(password.toLowerCase());
    }
}
