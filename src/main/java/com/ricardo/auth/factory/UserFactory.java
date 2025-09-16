package com.ricardo.auth.factory;

import com.ricardo.auth.core.PasswordPolicyService;
import com.ricardo.auth.domain.user.*;
import com.ricardo.auth.dto.CreateUserRequestDTO;
import com.ricardo.auth.dto.UpdateUserRequestDTO;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.UUID;

/**
 * The type User factory.
 */
public class UserFactory implements AuthUserFactory<User, AppRole, UUID> {
    private final PasswordEncoder passwordEncoder;
    private final PasswordPolicyService passwordPolicyService;

    /**
     * Instantiates a new User controller.
     *
     * @param passwordEncoder       the password encoder
     * @param passwordPolicyService the password policy service
     */
    public UserFactory(PasswordEncoder passwordEncoder, PasswordPolicyService passwordPolicyService) {
        this.passwordEncoder = passwordEncoder;
        this.passwordPolicyService = passwordPolicyService;
    }

    /**
     * Create user.
     *
     * @param request the request
     * @return the user
     */
    @Override
    public User create(CreateUserRequestDTO request){
        Username name = Username.valueOf(request.getUsername());
        Email email = Email.valueOf(request.getEmail());
        Password password = Password.valueOf(request.getPassword(), passwordEncoder, passwordPolicyService);

        return new User(name, email, password);
    }
}
