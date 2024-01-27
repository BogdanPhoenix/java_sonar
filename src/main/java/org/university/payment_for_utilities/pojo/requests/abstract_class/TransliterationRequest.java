package org.university.payment_for_utilities.pojo.requests.abstract_class;

import jakarta.persistence.MappedSuperclass;
import lombok.*;
import lombok.experimental.SuperBuilder;

/**
 * An abstract class representing the query structure that must necessarily contain the name of the entity in Ukrainian and English that can be used to interact with the system.
 */
@Getter
@Setter
@ToString
@SuperBuilder
@MappedSuperclass
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(callSuper = false)
public abstract class TransliterationRequest extends Request {
    private String uaName;
    private String enName;

    @Override
    public boolean isEmpty() {
        return this.uaName.isBlank() ||
                this.enName.isBlank();
    }

    protected static TransliterationRequest initEmpty(@NonNull TransliterationRequestBuilder<?, ?> builder) {
        return builder
                .uaName("")
                .enName("")
                .build();
    }
}
