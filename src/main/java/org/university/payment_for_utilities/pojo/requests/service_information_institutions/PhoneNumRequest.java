package org.university.payment_for_utilities.pojo.requests.service_information_institutions;

import jakarta.persistence.MappedSuperclass;
import lombok.*;
import lombok.experimental.SuperBuilder;
import org.jetbrains.annotations.Contract;
import org.university.payment_for_utilities.pojo.requests.abstract_class.Request;

@Getter
@Setter
@ToString
@SuperBuilder
@MappedSuperclass
@AllArgsConstructor
@NoArgsConstructor
@EqualsAndHashCode(callSuper = false)
public class PhoneNumRequest extends Request {
    private String number;

    @Override
    public boolean isEmpty() {
        return this.number.isBlank();
    }

    @Contract(" -> new")
    public static @NonNull PhoneNumRequest empty(){
        return PhoneNumRequest
                .builder()
                .number("")
                .build();
    }
}
