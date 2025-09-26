package com.ricardo.auth.core;

/**
 * The interface Email sender service.
 */
public interface EmailSenderService {
    /**
     * Send email boolean.
     *
     * @param to      the to
     * @param subject the subject
     * @param body    the body
     * @return the boolean
     */
    boolean sendEmail(String to, String subject, String body);
}
