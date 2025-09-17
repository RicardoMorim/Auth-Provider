package com.ricardo.auth.service;

import org.springframework.stereotype.Component;
import com.ricardo.auth.domain.DatabaseOperation;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class UserMetricsService {
    private final List<DatabaseOperation> operations = new ArrayList<>();

    public void recordOperation(String operation, long startTime, long endTime, boolean success) {
        operations.add(new DatabaseOperation(operation, startTime, endTime, success));
    }

    public List<DatabaseOperation> getOperations() {
        return new ArrayList<>(operations);
    }

    public void clear() {
        operations.clear();
    }
}