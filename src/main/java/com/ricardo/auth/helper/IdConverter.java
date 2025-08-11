package com.ricardo.auth.helper;

public interface IdConverter<ID> {

    ID fromString(String id);
    String toString(ID id);
}
