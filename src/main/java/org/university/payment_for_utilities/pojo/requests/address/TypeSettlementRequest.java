package org.university.payment_for_utilities.pojo.requests.address;

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
public class TypeSettlementRequest extends TransliterationRequest {
    @Contract(" -> new")
    public static @NonNull TypeSettlementRequest empty(){
        return (TypeSettlementRequest) initEmpty(TypeSettlementRequest.builder());
    }
}
