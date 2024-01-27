package org.university.payment_for_utilities.domains.abstract_class;

import jakarta.persistence.Column;
import jakarta.persistence.MappedSuperclass;
import lombok.*;
import lombok.experimental.SuperBuilder;
import org.hibernate.annotations.DynamicInsert;
import org.hibernate.annotations.DynamicUpdate;

@Getter
@Setter
@ToString
@SuperBuilder
@DynamicUpdate
@DynamicInsert
@MappedSuperclass
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(callSuper = true)
public class CounterSearcher extends ReceiptSearcher {
    public static final Float EMPTY_COUNTER = -1.0f;

    @Column(name = "prev_value_counter", nullable = false)
    @NonNull
    private Float prevValueCounter;

    @Column(name = "current_value_counter", nullable = false)
    @NonNull
    private Float currentValueCounter;

    @Override
    public boolean isEmpty() {
        return super.isEmpty() ||
                prevValueCounter.equals(EMPTY_COUNTER) ||
                currentValueCounter.equals(EMPTY_COUNTER);
    }

    protected static void initEmpty(@NonNull CounterSearcherBuilder<?, ?> builder) {
        ReceiptSearcher.initEmpty(builder);
        builder
                .prevValueCounter(EMPTY_COUNTER)
                .currentValueCounter(EMPTY_COUNTER);
    }
}
