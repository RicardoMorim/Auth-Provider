package com.ricardo.auth.service;

import com.ricardo.auth.autoconfig.AuthProperties;
import com.ricardo.auth.core.EmailSenderService;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.util.StringUtils;


/**
 * The type Email sender service.
 */
@AllArgsConstructor
@Slf4j
public class EmailSenderServiceImpl implements EmailSenderService {

    private final JavaMailSender mailSender;
    private final AuthProperties authProperties;

    @Override
    public boolean sendEmail(String to, String subject, String body) {
        try {
            log.info("Sending email to: {}, subject: {}", to, subject);

            if (to == null || to.isEmpty()) {
                log.warn("Recipient email address is null or empty.");
                return false;
            }

            if (subject == null || subject.isEmpty()) {
                log.warn("Email subject is null or empty.");
                return false;
            }

            if (body == null || body.isEmpty()) {
                log.warn("Email body is null or empty.");
                return false;
            }

            var emailCfg = authProperties.getEmail();
            if (emailCfg == null || !StringUtils.hasText(emailCfg.getFromAddress())) {
                log.warn("Sender email address is not configured.");
                return false;
            }
            SimpleMailMessage message = new SimpleMailMessage();
            message.setTo(to);
            message.setSubject(subject);
            message.setText(body);
            message.setFrom(authProperties.getEmail().getFromAddress());

            mailSender.send(message);
            log.info("Email sent successfully to: {}", to);
            return true;
        } catch (Exception e) {
            log.error("Failed to send email to: {}, error: {}", to, e.getMessage(), e);
            return false;
        }
    }
}
