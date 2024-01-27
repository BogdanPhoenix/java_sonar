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
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(callSuper = false)
public class WebsiteRequest extends Request {
    private String value;

    @Override
    public boolean isEmpty() {
        return value.isBlank();
    }

    @Contract(" -> new")
    public static @NonNull WebsiteRequest empty(){
        return WebsiteRequest
                .builder()
                .value("")
                .build();
    }
}
