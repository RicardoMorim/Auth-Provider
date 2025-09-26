package com.ricardo.auth.service;

import com.ricardo.auth.autoconfig.AuthProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mail.MailException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Tests for EmailSenderServiceImpl.
 * Tests email sending functionality and error handling.
 *
 * @since 3.1.0
 */
@ExtendWith(MockitoExtension.class)
class EmailSenderServiceImplTest {

    @Mock
    private JavaMailSender mailSender;

    private AuthProperties authProperties;
    private EmailSenderServiceImpl emailService;

    /**
     * Sets up.
     */
    @BeforeEach
    void setUp() {
        authProperties = createAuthProperties();
        emailService = new EmailSenderServiceImpl(mailSender, authProperties);
    }

    /**
     * Send email with valid parameters should send successfully.
     */
    @Test
    void sendEmail_WithValidParameters_ShouldSendSuccessfully() {
        // Given
        String to = "user@example.com";
        String subject = "Test Subject";
        String body = "Test Body";

        // When
        boolean result = emailService.sendEmail(to, subject, body);

        // Then
        assertThat(result).isTrue();
        
        ArgumentCaptor<SimpleMailMessage> messageCaptor = ArgumentCaptor.forClass(SimpleMailMessage.class);
        verify(mailSender).send(messageCaptor.capture());
        
        SimpleMailMessage sentMessage = messageCaptor.getValue();
        assertThat(sentMessage.getTo()).containsExactly(to);
        assertThat(sentMessage.getSubject()).isEqualTo(subject);
        assertThat(sentMessage.getText()).isEqualTo(body);
        assertThat(sentMessage.getFrom()).isEqualTo("noreply@test.com");
    }


    /**
     * Send email with null to should return false.
     */
    @Test
    void sendEmail_WithNullTo_ShouldReturnFalse() {
        // When
        boolean result = emailService.sendEmail(null, "Subject", "Body");

        // Then
        assertThat(result).isFalse();
        verify(mailSender, never()).send(any(SimpleMailMessage.class));
    }

    /**
     * Send email with empty to should return false.
     */
    @Test
    void sendEmail_WithEmptyTo_ShouldReturnFalse() {
        // When
        boolean result = emailService.sendEmail("", "Subject", "Body");

        // Then
        assertThat(result).isFalse();
        verify(mailSender, never()).send(any(SimpleMailMessage.class));
    }

    /**
     * Send email with null subject should return false.
     */
    @Test
    void sendEmail_WithNullSubject_ShouldReturnFalse() {
        // When
        boolean result = emailService.sendEmail("user@example.com", null, "Body");

        // Then
        assertThat(result).isFalse();
        verify(mailSender, never()).send(any(SimpleMailMessage.class));
    }

    /**
     * Send email with null body should return false.
     */
    @Test
    void sendEmail_WithNullBody_ShouldReturnFalse() {
        // When
        boolean result = emailService.sendEmail("user@example.com", "Subject", null);

        // Then
        assertThat(result).isFalse();
        verify(mailSender, never()).send(any(SimpleMailMessage.class));
    }

    /**
     * Send email when mail sender throws exception should return false.
     */
    @Test
    void sendEmail_WhenMailSenderThrowsException_ShouldReturnFalse() {
        // Given
        doThrow(new MailException("SMTP server unavailable") {}).when(mailSender)
            .send(any(SimpleMailMessage.class));

        // When
        boolean result = emailService.sendEmail("user@example.com", "Subject", "Body");

        // Then
        assertThat(result).isFalse();
        verify(mailSender).send(any(SimpleMailMessage.class));
    }

    /**
     * Send email with invalid email format should still attempt to send.
     */
    @Test
    void sendEmail_WithInvalidEmailFormat_ShouldStillAttemptToSend() {
        // Given
        String invalidEmail = "invalid-email-format";

        // When
        boolean result = emailService.sendEmail(invalidEmail, "Subject", "Body");

        // Then
        // The service doesn't validate email format - that's done at controller level
        assertThat(result).isTrue();
        verify(mailSender).send(any(SimpleMailMessage.class));
    }

    /**
     * Send email with long subject should send successfully.
     */
    @Test
    void sendEmail_WithLongSubject_ShouldSendSuccessfully() {
        // Given
        String longSubject = "A".repeat(1000);

        // When
        boolean result = emailService.sendEmail("user@example.com", longSubject, "Body");

        // Then
        assertThat(result).isTrue();
        
        ArgumentCaptor<SimpleMailMessage> messageCaptor = ArgumentCaptor.forClass(SimpleMailMessage.class);
        verify(mailSender).send(messageCaptor.capture());
        
        SimpleMailMessage sentMessage = messageCaptor.getValue();
        assertThat(sentMessage.getSubject()).isEqualTo(longSubject);
    }

    /**
     * Send email with special characters should send successfully.
     */
    @Test
    void sendEmail_WithSpecialCharacters_ShouldSendSuccessfully() {
        // Given
        String specialCharsBody = "Test with special chars: äöü ñ €£¥ 中文 🚀";

        // When
        boolean result = emailService.sendEmail("user@example.com", "Subject", specialCharsBody);

        // Then
        assertThat(result).isTrue();
        
        ArgumentCaptor<SimpleMailMessage> messageCaptor = ArgumentCaptor.forClass(SimpleMailMessage.class);
        verify(mailSender).send(messageCaptor.capture());
        
        SimpleMailMessage sentMessage = messageCaptor.getValue();
        assertThat(sentMessage.getText()).isEqualTo(specialCharsBody);
    }

    private AuthProperties createAuthProperties() {
        AuthProperties properties = new AuthProperties();
        
        AuthProperties.Email email = new AuthProperties.Email();
        email.setFromAddress("noreply@test.com");
        email.setFromName("Test App");
        properties.setEmail(email);
        
        return properties;
    }
}
