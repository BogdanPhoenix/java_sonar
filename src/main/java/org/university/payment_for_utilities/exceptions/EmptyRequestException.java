package org.university.payment_for_utilities.exceptions;

/**
 * An exception thrown when a request for processing is received that is empty or invalid.
 * Usually used to mark situations where processing empty requests is not possible.
 */

public class EmptyRequestException extends RuntimeException {
    public EmptyRequestException(String message) {
        super(message);
    }
}
