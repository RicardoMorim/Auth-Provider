package com.ricardo.auth.core;

import org.springframework.context.ApplicationEvent;

/**
 * The interface Publisher.
 */
public interface Publisher {
    /**
     * Publish event.
     *
     * @param event the event
     */
    void publishEvent(ApplicationEvent event);

    /**
     * Publish event.
     *
     * @param event the event
     */
    void publishEvent(Object event);
}
