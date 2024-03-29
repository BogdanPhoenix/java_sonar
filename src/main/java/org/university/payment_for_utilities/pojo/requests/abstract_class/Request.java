package org.university.payment_for_utilities.pojo.requests.abstract_class;

import jakarta.persistence.MappedSuperclass;
import lombok.*;
import lombok.experimental.SuperBuilder;

/**
 * An abstract class representing the query structure that can be used to interact with the system.
 */
@ToString
@SuperBuilder
@MappedSuperclass
@EqualsAndHashCode
@NoArgsConstructor
public abstract class Request {
    /**
     * Checks if the request is empty.
     *
     * @return true if the request does not contain at least one empty attribute, otherwise false.
     */
    public abstract boolean isEmpty();
}
