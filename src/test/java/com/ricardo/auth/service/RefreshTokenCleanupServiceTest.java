package com.ricardo.auth.service;

import com.ricardo.auth.autoconfig.AuthProperties;
import com.ricardo.auth.repository.refreshToken.RefreshTokenRepository;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class RefreshTokenCleanupServiceTest {

    @Test
    void cleanupExpiredTokens_shouldDoNothing_whenAutoCleanupDisabled() {
        RefreshTokenRepository repository = mock(RefreshTokenRepository.class);
        AuthProperties properties = new AuthProperties();
        properties.getRefreshTokens().setAutoCleanup(false);

        RefreshTokenCleanupService service = new RefreshTokenCleanupService(repository, properties);

        service.cleanupExpiredTokens();

        verifyNoInteractions(repository);
    }

    @Test
    void cleanupExpiredTokens_shouldDeleteExpiredTokens_whenAutoCleanupEnabled() {
        RefreshTokenRepository repository = mock(RefreshTokenRepository.class);
        when(repository.deleteExpiredTokens(any(Instant.class))).thenReturn(3);
        AuthProperties properties = new AuthProperties();
        properties.getRefreshTokens().setAutoCleanup(true);

        RefreshTokenCleanupService service = new RefreshTokenCleanupService(repository, properties);

        service.cleanupExpiredTokens();

        verify(repository).deleteExpiredTokens(any(Instant.class));
    }

    @Test
    void cleanupExpiredTokens_shouldSwallowExceptionsAndContinue() {
        RefreshTokenRepository repository = mock(RefreshTokenRepository.class);
        when(repository.deleteExpiredTokens(any(Instant.class))).thenThrow(new RuntimeException("boom"));
        AuthProperties properties = new AuthProperties();
        properties.getRefreshTokens().setAutoCleanup(true);

        RefreshTokenCleanupService service = new RefreshTokenCleanupService(repository, properties);

        assertDoesNotThrow(service::cleanupExpiredTokens);
        verify(repository).deleteExpiredTokens(any(Instant.class));
    }
}
