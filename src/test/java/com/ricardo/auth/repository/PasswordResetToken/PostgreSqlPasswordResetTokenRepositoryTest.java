package com.ricardo.auth.repository.PasswordResetToken;

import com.ricardo.auth.autoconfig.AuthProperties;
import org.junit.jupiter.api.Test;

import javax.sql.DataSource;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

class PostgreSqlPasswordResetTokenRepositoryTest {

    @Test
    void constructor_WithSafeTableName_ShouldInitialize() {
        AuthProperties properties = new AuthProperties();
        properties.getRepository().getDatabase().setPasswordResetTokensTable("password_reset_tokens");

        assertThatCode(() -> new PostgreSqlPasswordResetTokenRepository(mock(DataSource.class), properties))
                .doesNotThrowAnyException();
    }

    @Test
    void constructor_WithInvalidTableName_ShouldThrow() {
        AuthProperties properties = new AuthProperties();
        properties.getRepository().getDatabase().setPasswordResetTokensTable("password_reset_tokens; DROP TABLE users;");

        assertThatThrownBy(() -> new PostgreSqlPasswordResetTokenRepository(mock(DataSource.class), properties))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Invalid password reset tokens table name");
    }
}
