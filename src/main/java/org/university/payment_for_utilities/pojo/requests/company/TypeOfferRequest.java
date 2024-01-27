package org.university.payment_for_utilities.pojo.requests.company;

import jakarta.persistence.MappedSuperclass;
import lombok.*;
import lombok.experimental.SuperBuilder;
import org.jetbrains.annotations.Contract;
import org.university.payment_for_utilities.domains.service_information_institutions.UnitMeasurement;
import org.university.payment_for_utilities.pojo.requests.abstract_class.TransliterationRequest;

@Getter
@Setter
@ToString
@SuperBuilder
@MappedSuperclass
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(callSuper = true)
public class TypeOfferRequest extends TransliterationRequest {
    private UnitMeasurement unitMeasurement;
    @Override
    public boolean isEmpty() {
        return super.isEmpty() ||
                this.unitMeasurement.isEmpty();
    }

    @Contract(" -> new")
    public static @NonNull TypeOfferRequest empty(){
        var entity = (TypeOfferRequest) initEmpty(TypeOfferRequest.builder());
        entity.setUnitMeasurement(UnitMeasurement.empty());
        return entity;
    }
}
