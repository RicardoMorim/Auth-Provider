package com.ricardo.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
public class LoginRequestDTO {
    private String Email;
    private String password;
}

