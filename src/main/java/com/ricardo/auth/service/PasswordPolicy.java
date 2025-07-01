package com.ricardo.auth.service;

import com.ricardo.auth.autoconfig.AuthProperties;
import com.ricardo.auth.core.PasswordPolicyService;

import java.security.SecureRandom;
import java.util.Collections;
import java.util.Set;

import static com.ricardo.auth.helper.CommonPasswordHelper.isCommonPassword;
import static com.ricardo.auth.helper.CommonPasswordHelper.loadCommonPasswords;

/**
 * The type Password policy.
 * Bean Creation is handled in the {@link com.ricardo.auth.autoconfig.AuthAutoConfiguration}
 */
public class PasswordPolicy implements PasswordPolicyService {
    private final boolean requireUpperCase;
    private final boolean requireLowerCase;
    private final boolean requireDigit;
    private final boolean requireSpecialChar;
    private final String specialCharacters;
    private final int minLength;
    private final int maxLength;
    private final boolean preventCommonPasswords;
    private final Set<String> commonPasswords;

    private final SecureRandom secureRandom = new SecureRandom();


    /**
     * Instantiates a new Password policy.
     *
     * @param authProperties the auth properties
     */
    public PasswordPolicy(AuthProperties authProperties) {
        this.requireDigit = authProperties.getPasswordPolicy().isRequireDigits();
        this.requireUpperCase = authProperties.getPasswordPolicy().isRequireUppercase();
        this.requireLowerCase = authProperties.getPasswordPolicy().isRequireLowercase();
        this.requireSpecialChar = authProperties.getPasswordPolicy().isRequireSpecialChars();
        this.specialCharacters = authProperties.getPasswordPolicy().getAllowedSpecialChars();
        this.minLength = authProperties.getPasswordPolicy().getMinLength();
        this.maxLength = authProperties.getPasswordPolicy().getMaxLength();
        this.preventCommonPasswords = authProperties.getPasswordPolicy().isPreventCommonPasswords();
        if (preventCommonPasswords) {
            this.commonPasswords = loadCommonPasswords(authProperties.getPasswordPolicy().getCommonPasswordsFilePath());
        } else {
            this.commonPasswords = Collections.emptySet();
        }

        validateInputs();
    }

    private void validateInputs() {
        if (minLength < 1 || maxLength < minLength) {
            throw new IllegalArgumentException("Invalid password length configuration: minLength must be >= 1 and maxLength must be >= minLength.");
        }
        if ((specialCharacters == null || specialCharacters.isEmpty()) && requireSpecialChar) {
            throw new IllegalArgumentException("Special characters cannot be null or empty when requiring special characters.");
        }
    }


    @Override
    public boolean validatePassword(String passwordInput) {
        String password = passwordInput != null ? passwordInput.trim() : null;
        if (password == null || password.length() < minLength) {
            throw new IllegalArgumentException("Password must be at least " + minLength + " characters long.");
        }

        if (password.length() > maxLength) {
            throw new IllegalArgumentException("Password must not exceed " + maxLength + " characters.");
        }

        if (preventCommonPasswords && isCommonPassword(password, this.commonPasswords)) {
            throw new IllegalArgumentException("Password is too common and does not meet security requirements.");
        }

        boolean hasUpperCase = !requireUpperCase;
        boolean hasLowerCase = !requireLowerCase;
        boolean hasDigit = !requireDigit;
        boolean hasSpecialChar = !requireSpecialChar;

        for (char c : password.toCharArray()) {
            if (Character.isUpperCase(c)) {
                hasUpperCase = true;
            } else if (Character.isLowerCase(c)) {
                hasLowerCase = true;
            } else if (Character.isDigit(c)) {
                hasDigit = true;
            } else if (specialCharacters.indexOf(c) >= 0) {
                hasSpecialChar = true;
            }
        }

        if (requireUpperCase && !hasUpperCase) {
            throw new IllegalArgumentException("Password must contain at least one uppercase letter.");
        }

        if (requireLowerCase && !hasLowerCase) {
            throw new IllegalArgumentException("Password must contain at least one lowercase letter.");
        }

        if (requireDigit && !hasDigit) {
            throw new IllegalArgumentException("Password must contain at least one digit.");
        }

        if (requireSpecialChar && !hasSpecialChar) {
            throw new IllegalArgumentException("Password must contain at least one special character: " + specialCharacters);
        }

        // If all conditions are met, return true
        return hasUpperCase && hasLowerCase && hasDigit && hasSpecialChar;
    }

    @Override
    public String generateSecurePassword() {
        StringBuilder password = new StringBuilder();

        // Ensure at least one character from each required category
        if (requireLowerCase) {
            String lowerCase = "abcdefghijklmnopqrstuvwxyz";
            password.append(lowerCase.charAt(secureRandom.nextInt(lowerCase.length())));
        }

        if (requireUpperCase) {
            String upperCase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            password.append(upperCase.charAt(secureRandom.nextInt(upperCase.length())));
        }

        if (requireDigit) {
            String digits = "0123456789";
            password.append(digits.charAt(secureRandom.nextInt(digits.length())));
        }

        if (requireSpecialChar) {
            password.append(specialCharacters.charAt(secureRandom.nextInt(specialCharacters.length())));
        }

        // Fill the rest with random characters
        String allChars = buildAllCharacters();
        while (password.length() < minLength) {
            password.append(allChars.charAt(secureRandom.nextInt(allChars.length())));
        }

        // Shuffle the password to avoid predictable patterns
        return shufflePassword(password.toString());
    }


    /**
     * Builds a string containing all allowed characters based on the password policy requirements.
     *
     * @return a string containing all allowed characters for password generation
     */
    private String buildAllCharacters() {
        StringBuilder allChars = new StringBuilder();

        if (requireLowerCase) {
            allChars.append("abcdefghijklmnopqrstuvwxyz");
        }

        if (requireUpperCase) {
            allChars.append("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
        }

        if (requireDigit) {
            allChars.append("0123456789");
        }

        if (requireSpecialChar) {
            allChars.append(specialCharacters);
        }

        // If no requirements are set, include all character types
        if (allChars.isEmpty()) {
            allChars.append("abcdefghijklmnopqrstuvwxyz")
                    .append("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
                    .append("0123456789")
                    .append(specialCharacters != null ? specialCharacters : "!@#$%^&*");
        }

        return allChars.toString();
    }

    private String shufflePassword(String password) {
        StringBuilder result = new StringBuilder(password);

        // Fisher-Yates shuffle algorithm with SecureRandom
        for (int i = result.length() - 1; i > 0; i--) {
            int j = secureRandom.nextInt(i + 1);
            char temp = result.charAt(i);
            result.setCharAt(i, result.charAt(j));
            result.setCharAt(j, temp);
        }

        return result.toString();
    }
}
