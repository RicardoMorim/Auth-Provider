package com.ricardo.auth.service;

import com.ricardo.auth.core.Publisher;
import lombok.AllArgsConstructor;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;

/**
 * The type Event publisher.
 */
@AllArgsConstructor
@Service
public class EventPublisher implements Publisher {

    private final ApplicationEventPublisher applicationEventPublisher;

    @Override
    public void publishEvent(Object event) {
        applicationEventPublisher.publishEvent(event);
    }

    @Override
    public void publishEvent(org.springframework.context.ApplicationEvent event) {
        this.publishEvent((Object) event);
    }
}
