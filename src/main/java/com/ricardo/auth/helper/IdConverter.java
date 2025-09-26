package com.ricardo.auth.helper;

/**
 * The interface Id converter.
 *
 * @param <ID> the type parameter
 */
public interface IdConverter<ID> {

    /**
     * From string id.
     *
     * @param id the id
     * @return the id
     */
    ID fromString(String id);

    /**
     * To string string.
     *
     * @param id the id
     * @return the string
     */
    String toString(ID id);
}
