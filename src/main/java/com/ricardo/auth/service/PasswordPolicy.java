package com.ricardo.auth.service;

import com.ricardo.auth.autoconfig.AuthProperties;
import com.ricardo.auth.core.PasswordPolicyService;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.Set;

import static com.ricardo.auth.helper.CommonPasswordHelper.isCommonPassword;
import static com.ricardo.auth.helper.CommonPasswordHelper.loadCommonPasswords;

/**
 * The type Password policy.
 */
@Service
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
    public boolean validatePassword(String password) {

        if (password == null || password.length() < minLength || password.length() > maxLength) {
            return false;
        }

        if (preventCommonPasswords && isCommonPassword(password, this.commonPasswords)) {
            return false;
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
        return hasUpperCase && hasLowerCase && hasDigit && hasSpecialChar;
    }

    @Override
    public String generateSecurePassword() {
        String LowerCasecharacters = "abcdefghijklmnopqrstuvwxyz";
        String UpperCasecharacters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        String digits = "0123456789";
        String specialCharacters = "!@#$%^&*()-_=+[]{}|;:',.<>?";

        String[] allCharacters = {
                LowerCasecharacters, UpperCasecharacters, digits, specialCharacters
        };

        StringBuilder password = new StringBuilder();

        // Ensure at least one character from each category
        password.append(LowerCasecharacters.charAt((int) (Math.random() * LowerCasecharacters.length())));
        password.append(UpperCasecharacters.charAt((int) (Math.random() * UpperCasecharacters.length())));
        password.append(digits.charAt((int) (Math.random() * digits.length())));
        password.append(specialCharacters.charAt((int) (Math.random() * specialCharacters.length())));

        // Fill the rest of the password with random characters from all categories
        for (int i = 4; i < 12; i++) { // Total length of 12 characters
            String randomCategory = allCharacters[(int) (Math.random() * allCharacters.length)];
            password.append(randomCategory.charAt((int) (Math.random() * randomCategory.length())));
        }

        // Shuffle the characters to ensure randomness
        StringBuilder shuffledPassword = new StringBuilder();
        while (!password.isEmpty()) {
            int index = (int) (Math.random() * password.length());
            shuffledPassword.append(password.charAt(index));
            password.deleteCharAt(index);
        }

        return shuffledPassword.toString();
    }
}
