package com.ricardo.auth.domain;

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

    Object getId();

    String getEmail();

    void setEmail(String email);

    void setUsername(String username);

    void setPassword(String password);

    Set<R> getRoles();

    void addRole(R role);
}