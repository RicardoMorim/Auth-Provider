package com.ricardo.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * The type Login request dto.
 */
@AllArgsConstructor
@Getter
public class LoginRequestDTO {
    private String Email;
    private String password;
}

