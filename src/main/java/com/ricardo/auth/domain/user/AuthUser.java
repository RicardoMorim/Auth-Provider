package com.ricardo.auth.domain.user;

import com.ricardo.auth.core.Role;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Set;

/**
 * Define o contrato para uma entidade de utilizador que pode ser usada
 * pelo pacote de autenticação. Qualquer classe de utilizador personalizada deve
 * implementar esta interface. Estende UserDetails para integração com o Spring Security.
 *
 * @param <R> O tipo da Role, que deve implementar a interface Role.
 */
public interface AuthUser<R extends Role> extends UserDetails {

    /**
     * Gets id.
     *
     * @return the id
     */
    Object getId();

    /**
     * Gets email.
     *
     * @return the email
     */
    String getEmail();

    /**
     * Sets email.
     *
     * @param email the email
     */
    void setEmail(String email);

    /**
     * Sets username.
     *
     * @param username the username
     */
    void setUsername(String username);

    /**
     * Sets password.
     *
     * @param password the password
     */
    void setPassword(String password);

    /**
     * Gets roles.
     *
     * @return the roles
     */
    Set<R> getRoles();

    /**
     * Add role.
     *
     * @param role the role
     */
    void addRole(R role);

    /**
     * Remove role.
     *
     * @param role the role
     */
    void removeRole(R role);
}