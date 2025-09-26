package com.ricardo.auth.helper;

import com.ricardo.auth.domain.user.Email;
import com.ricardo.auth.domain.user.Username;

public class UserVoConverter implements VoConverter<Username, Email> {

    /**
     * @param username
     * @return
     */
    @Override
    public Username usernameFromString(String username) {
        return Username.valueOf(username);
    }

    /**
     * @param username
     * @return
     */
    @Override
    public Email emailFromString(String username) {
        return Email.valueOf(username);
    }

    /**
     * @param username
     * @return
     */
    @Override
    public String usernameToString(Username username) {
        return username.toString();
    }

    /**
     * @param email
     * @return
     */
    @Override
    public String emailToString(Email email) {
        return email.toString();
    }
}
