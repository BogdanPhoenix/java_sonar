package org.university.payment_for_utilities.exceptions;

/**
 * An exception that occurs when the received data is invalid or incorrect.
 * Typically thrown when processing user input or parameters,
 * that do not meet the expected format or requirements.
 */

public class InvalidInputDataException extends RuntimeException {
    public InvalidInputDataException(String message) {
        super(message);
    }
}
