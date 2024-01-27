package org.university.payment_for_utilities.pojo.requests.abstract_class;

import jakarta.persistence.MappedSuperclass;
import lombok.*;
import lombok.experimental.SuperBuilder;

import static org.university.payment_for_utilities.domains.abstract_class.CounterSearcher.EMPTY_COUNTER;

@Getter
@Setter
@ToString
@SuperBuilder
@MappedSuperclass
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(callSuper = true)
public abstract class CounterSearcherRequest extends ReceiptSearcherRequest {
    private Float prevValueCounter;
    private Float currentValueCounter;

    @Override
    public boolean isEmpty() {
        return super.isEmpty() ||
                prevValueCounter.equals(EMPTY_COUNTER) ||
                currentValueCounter.equals(EMPTY_COUNTER);
    }
}
