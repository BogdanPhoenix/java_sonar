package org.university.payment_for_utilities.exceptions;

/**
 * An exception thrown when an object is not found in the database.
 * Used when trying to get an object by a specific identifier, but its absence
 * leads to a runtime exception.
 */

public class NotFindEntityInDataBaseException extends RuntimeException{
    public NotFindEntityInDataBaseException(String message) {
        super(message);
    }
}
