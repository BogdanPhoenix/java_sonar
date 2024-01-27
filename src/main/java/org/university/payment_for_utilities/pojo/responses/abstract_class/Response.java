package org.university.payment_for_utilities.pojo.responses.abstract_class;

import jakarta.persistence.MappedSuperclass;
import lombok.*;
import lombok.experimental.SuperBuilder;

import java.time.LocalDateTime;

/**
 * An abstract class that represents a response structure that can be used to interact with the system.
 */
@Getter
@Setter
@ToString
@SuperBuilder
@MappedSuperclass
@EqualsAndHashCode
@NoArgsConstructor
@AllArgsConstructor
public abstract class Response {
    private Long id;

    @EqualsAndHashCode.Exclude
    private LocalDateTime createDate;

    @EqualsAndHashCode.Exclude
    private LocalDateTime updateDate;
}
