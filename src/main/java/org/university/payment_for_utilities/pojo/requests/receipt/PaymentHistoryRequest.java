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
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(callSuper = true)
public class PaymentHistoryRequest extends CounterSearcherRequest {
    private String finalPaymentAmount;

    @Override
    public boolean isEmpty() {
        return super.isEmpty() ||
                finalPaymentAmount.isBlank();
    }

    @Contract(" -> new")
    public static @NonNull PaymentHistoryRequest empty() {
        return PaymentHistoryRequest
                .builder()
                .receipt(Receipt.empty())
                .prevValueCounter(EMPTY_COUNTER)
                .currentValueCounter(EMPTY_COUNTER)
                .finalPaymentAmount("")
                .build();
    }
}
