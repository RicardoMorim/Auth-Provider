package com.ricardo.auth.repository.PasswordResetToken;

import com.ricardo.auth.domain.passwordresettoken.PasswordResetToken;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class JpaPasswordResetTokenRepositoryDefaultsTest {

    @Test
    void countResetAttemptsForEmailSince_WhenEmailBlank_ShouldReturnZero() {
        JpaPasswordResetTokenRepository repository = mock(
                JpaPasswordResetTokenRepository.class,
                withSettings().defaultAnswer(CALLS_REAL_METHODS)
        );

        int count = repository.countResetAttemptsForEmailSince("   ", Instant.now());

        assertThat(count).isZero();
        verify(repository, never()).countResetAttemptsForEmailSinceInternal(anyString(), any());
    }

    @Test
    void countResetAttemptsForEmailSince_WhenEmailValid_ShouldDelegateToInternal() {
        JpaPasswordResetTokenRepository repository = mock(
                JpaPasswordResetTokenRepository.class,
                withSettings().defaultAnswer(CALLS_REAL_METHODS)
        );
        when(repository.countResetAttemptsForEmailSinceInternal(eq("user@example.com"), any())).thenReturn(5);

        int count = repository.countResetAttemptsForEmailSince("user@example.com", Instant.now());

        assertThat(count).isEqualTo(5);
    }

    @Test
    void findAndExistsDefaultMethods_ShouldDelegateWithNow() {
        JpaPasswordResetTokenRepository repository = mock(
                JpaPasswordResetTokenRepository.class,
                withSettings().defaultAnswer(CALLS_REAL_METHODS)
        );

        PasswordResetToken token = new PasswordResetToken("abc", "user@example.com", Instant.now().plusSeconds(3600));
        when(repository.findByTokenAndNotUsed(eq("abc"), any())).thenReturn(Optional.of(token));
        when(repository.existsByTokenAndNotUsed(eq("abc"), any())).thenReturn(true);

        Optional<PasswordResetToken> found = repository.findByTokenAndNotUsed("abc");
        boolean exists = repository.existsByTokenAndNotUsed("abc");

        assertThat(found).isPresent();
        assertThat(exists).isTrue();
    }

    @Test
    void saveTokenDefaultMethod_ShouldDelegateToSave() {
        JpaPasswordResetTokenRepository repository = mock(
                JpaPasswordResetTokenRepository.class,
                withSettings().defaultAnswer(CALLS_REAL_METHODS)
        );

        PasswordResetToken token = new PasswordResetToken("abc", "user@example.com", Instant.now().plusSeconds(3600));
        when(repository.save(token)).thenReturn(token);

        PasswordResetToken saved = repository.saveToken(token);

        assertThat(saved).isSameAs(token);
        verify(repository).save(token);
    }
}
