package com.ricardo.auth.core;

public interface EmailSenderService {
    boolean sendEmail(String to, String subject, String body);
}
