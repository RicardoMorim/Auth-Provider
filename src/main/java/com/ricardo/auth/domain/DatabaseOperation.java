package com.ricardo.auth.domain;


public record DatabaseOperation(String operation, long startTime, long endTime, boolean success) {
}
