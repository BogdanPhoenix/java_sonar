package org.university.payment_for_utilities.pojo.requests.service_information_institutions;

import jakarta.persistence.MappedSuperclass;
import lombok.*;
import lombok.experimental.SuperBuilder;
import org.jetbrains.annotations.Contract;
import org.university.payment_for_utilities.pojo.requests.abstract_class.TransliterationRequest;

@Getter
@Setter
@ToString
@SuperBuilder
@MappedSuperclass
@AllArgsConstructor
@EqualsAndHashCode(callSuper = true)
public class UnitMeasurementRequest extends TransliterationRequest {
    @Contract(" -> new")
    public static @NonNull UnitMeasurementRequest empty(){
        return (UnitMeasurementRequest) initEmpty(UnitMeasurementRequest.builder());
    }
}
