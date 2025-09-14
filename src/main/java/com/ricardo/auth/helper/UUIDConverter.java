package com.ricardo.auth.helper;

import java.util.UUID;


public class UUIDConverter implements IdConverter<UUID> {
    @Override
    public UUID fromString(String id) {
        if (id == null || id.isEmpty()) {
            throw new IllegalArgumentException("ID cannot be null or empty");
        }
        return UUID.fromString(id);
    }

    @Override
    public String toString(UUID id) {
        if (id == null) {
            throw new IllegalArgumentException("UUID cannot be null");
        }
        return id.toString();
    }
}
