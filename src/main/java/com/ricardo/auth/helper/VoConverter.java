package com.ricardo.auth.helper;

import com.ricardo.auth.domain.user.Email;
import com.ricardo.auth.domain.user.Username;

public interface VoConverter <UsernameVo extends Username, EmailVo extends Email> {
    UsernameVo usernameFromString(String username);

    EmailVo emailFromString(String username);

    String usernameToString(UsernameVo username);

    String emailToString(EmailVo email);
}
