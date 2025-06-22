package com.ricardo.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
public class CreateUserRequestDTO {
    private String username;
    private String email;
    private String password;
}
