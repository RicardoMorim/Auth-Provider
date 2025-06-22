package com.ricardo.auth.core;

import java.util.List;

public interface AuthenticatedUser {
    String getEmail();
    List<String> getRoles();
}
