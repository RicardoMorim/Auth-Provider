package com.ricardo.auth.helper;

import com.ricardo.auth.domain.user.Email;
import com.ricardo.auth.domain.user.Username;

/**
 * The interface Vo converter.
 *
 * @param <UsernameVo> the type parameter
 * @param <EmailVo>    the type parameter
 */
public interface VoConverter<UsernameVo extends Username, EmailVo extends Email> {
    /**
     * Username from string username vo.
     *
     * @param username the username
     * @return the username vo
     */
    UsernameVo usernameFromString(String username);

    /**
     * Email from string email vo.
     *
     * @param username the username
     * @return the email vo
     */
    EmailVo emailFromString(String username);

    /**
     * Username to string string.
     *
     * @param username the username
     * @return the string
     */
    String usernameToString(UsernameVo username);

    /**
     * Email to string string.
     *
     * @param email the email
     * @return the string
     */
    String emailToString(EmailVo email);
}
