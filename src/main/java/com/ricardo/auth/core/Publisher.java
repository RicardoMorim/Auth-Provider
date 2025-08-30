package com.ricardo.auth.core;

import org.springframework.context.ApplicationEvent;

public interface Publisher {
    void publishEvent(ApplicationEvent event);
    void publishEvent(Object event);
}
