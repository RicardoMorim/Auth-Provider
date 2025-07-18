package com.ricardo.auth.dto;

import lombok.Getter;

import java.io.Serializable;

/**
 * The type User dto.
 */
@Getter
public class UserDTO implements Serializable {
    private String id;
    private String username;
    private String email;


    /**
     * Instantiates a new User dto.
     */
    public UserDTO() {
    }

    /**
     * Instantiates a new User dto.
     *
     * @param id       the id
     * @param username the username
     * @param email    the email
     */
    public UserDTO(String id, String username, String email) {
        this.id = id;
        this.username = username;
        this.email = email;
    }


    /**
     * Sets id.
     *
     * @param id the id
     */
    public void setId(String id) {
        this.id = id;
    }

    /**
     * Sets username.
     *
     * @param username the username
     */
    public void setUsername(String username) {
        this.username = username;
    }


    /**
     * Sets email.
     *
     * @param email the email
     */
    public void setEmail(String email) {
        this.email = email;
    }
}
