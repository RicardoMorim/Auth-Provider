package com.ricardo.auth.core;

/**
 * Interface a ser implementada por uma enum de Role definida pelo utilizador.
 * Permite que o pacote de autenticação seja genérico, garantindo que as roles
 * possam ser convertidas para uma representação de string para as claims do JWT
 * e para as authorities do Spring Security.
 */
public interface Role {
    /**
     * Retorna a representação em string da role.
     * Recomenda-se seguir a convenção do Spring Security
     * e prefixar os nomes das roles com "ROLE_", por exemplo, "ROLE_USER".
     *
     * @return A string de autoridade para a role.
     */
    String getAuthority();
}