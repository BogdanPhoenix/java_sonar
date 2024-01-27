package org.university.payment_for_utilities.pojo.requests.receipt;

import jakarta.persistence.MappedSuperclass;
import lombok.*;
import lombok.experimental.SuperBuilder;
import org.jetbrains.annotations.Contract;
import org.university.payment_for_utilities.domains.receipt.Receipt;
import org.university.payment_for_utilities.pojo.requests.abstract_class.CounterSearcherRequest;

import static org.university.payment_for_utilities.domains.abstract_class.CounterSearcher.EMPTY_COUNTER;


@Getter
@Setter
@ToString
@SuperBuilder
@MappedSuperclass
@AllArgsConstructor
@EqualsAndHashCode(callSuper = true)
public class BlockMeterReadingRequest extends CounterSearcherRequest {
    @Contract(" -> new")
    public static @NonNull BlockMeterReadingRequest empty() {
        return BlockMeterReadingRequest
                .builder()
                .receipt(Receipt.empty())
                .prevValueCounter(EMPTY_COUNTER)
                .currentValueCounter(EMPTY_COUNTER)
                .build();
    }
}
