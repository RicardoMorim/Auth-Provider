package com.ricardo.auth.dto;

import com.ricardo.auth.domain.AuthUser;

public class UserDTOMapper {
    public static UserDTO toDTO(com.ricardo.auth.domain.AuthUser<?> user) {
        if (user == null) {
            return null;
        }
        UserDTO userDTO = new UserDTO();
        userDTO.setId(String.valueOf(user.getId()));
        userDTO.setUsername(user.getUsername());
        userDTO.setEmail(user.getEmail());
        return userDTO;
    }
}