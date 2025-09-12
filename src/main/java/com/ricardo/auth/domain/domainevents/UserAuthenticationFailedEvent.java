package com.ricardo.auth.domain.domainevents;

import com.ricardo.auth.domain.domainevents.enums.AuthenticationFailedReason;

public record UserAuthenticationFailedEvent(String email, AuthenticationFailedReason reason){
}
