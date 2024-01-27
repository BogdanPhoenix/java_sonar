package org.university.payment_for_utilities.pojo.requests.address;

import jakarta.persistence.MappedSuperclass;
import lombok.*;
import lombok.experimental.SuperBuilder;
import org.jetbrains.annotations.Contract;
import org.university.payment_for_utilities.domains.address.SettlementName;
import org.university.payment_for_utilities.domains.address.TypeSettlement;
import org.university.payment_for_utilities.pojo.requests.abstract_class.Request;

@Getter
@Setter
@ToString
@SuperBuilder
@MappedSuperclass
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(callSuper = false)
public class SettlementRequest extends Request {
    private TypeSettlement type;
    private String zipCode;
    private SettlementName name;

    @Override
    public boolean isEmpty() {
        return this.type.isEmpty() ||
                this.zipCode.isBlank() ||
                this.name.isEmpty();
    }

    @Contract(" -> new")
    public static @NonNull SettlementRequest empty(){
        return SettlementRequest
                .builder()
                .type(TypeSettlement.empty())
                .zipCode("")
                .name(SettlementName.empty())
                .build();
    }
}
