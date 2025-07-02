package com.ricardo.auth.dto;

import com.ricardo.auth.domain.user.AuthUser;

/**
 * The type User dto mapper.
 */
public class UserDTOMapper {
    /**
     * To dto user dto.
     *
     * @param user the user
     * @return the user dto
     */
    public static UserDTO toDTO(AuthUser<?> user) {
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