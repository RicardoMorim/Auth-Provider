package com.ricardo.auth.dto;

import lombok.Getter;

import java.io.Serializable;

@Getter
public class UserDTO implements Serializable {
    private String id;
    private String username;
    private String email;


    public UserDTO() {
    }

    public UserDTO(String id, String username, String email) {
        this.id = id;
        this.username = username;
        this.email = email;
    }


    public void setId(String id) {
        this.id = id;
    }

    public void setusername(String username) {
        this.username = username;
    }


    public void setEmail(String email) {
        this.email = email;
    }
}
