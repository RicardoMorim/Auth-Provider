package com.ricardo.auth.domain.user.domainevents;

public record TooManyAuthRequestsEvent (String email) {
}
