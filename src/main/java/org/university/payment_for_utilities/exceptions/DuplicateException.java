package org.university.payment_for_utilities.exceptions;

/**
 * An exception that occurs when a duplicate of an object or other entity that should not be duplicated is detected.
 * Usually used to signal an unacceptable event in the context of object uniqueness.
 */

public class DuplicateException extends RuntimeException {
    public DuplicateException(String message){
        super(message);
    }
}
