package com.ricardo.auth.domain;


/**
 * The type Database operation.
 */
public record DatabaseOperation(String operation, long startTime, long endTime, boolean success) {
}
