package com.ricardo.auth.domain.user.domainevents;

import com.ricardo.auth.domain.user.domainevents.enums.AuthenticationFailedReason;

public record UserAuthenticationFailedEvent(String email, AuthenticationFailedReason reason){
}
