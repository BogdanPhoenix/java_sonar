package org.university.payment_for_utilities.pojo.responses.company;

import jakarta.persistence.MappedSuperclass;
import lombok.*;
import lombok.experimental.SuperBuilder;
import org.university.payment_for_utilities.domains.service_information_institutions.UnitMeasurement;
import org.university.payment_for_utilities.pojo.responses.abstract_class.TransliterationResponse;

@Getter
@Setter
@ToString
@SuperBuilder
@MappedSuperclass
@AllArgsConstructor
@EqualsAndHashCode(callSuper = true)
public class TypeOfferResponse extends TransliterationResponse {
    private UnitMeasurement unitMeasurement;
}
