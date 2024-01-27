package org.university.payment_for_utilities.domains.receipt;

import jakarta.persistence.*;
import lombok.*;
import lombok.experimental.SuperBuilder;
import org.hibernate.annotations.DynamicInsert;
import org.hibernate.annotations.DynamicUpdate;
import org.jetbrains.annotations.Contract;
import org.university.payment_for_utilities.domains.abstract_class.CounterSearcher;

import java.math.BigDecimal;

import static org.university.payment_for_utilities.services.implementations.tools.FinanceTools.EMPTY_BIG_DECIMAL;

@Entity
@Getter
@Setter
@ToString
@SuperBuilder
@DynamicUpdate
@DynamicInsert
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(callSuper = true)
@Table(name = "payment_history")
public class PaymentHistory extends CounterSearcher {
    @Column(name = "final_payment_amount", nullable = false)
    @NonNull
    private BigDecimal finalPaymentAmount;

    @Override
    public boolean isEmpty() {
        return super.isEmpty() ||
                finalPaymentAmount.equals(EMPTY_BIG_DECIMAL);
    }

    @Contract(" -> new")
    public static @NonNull PaymentHistory empty() {
        var builder = builder();
        CounterSearcher.initEmpty(builder);

        return builder
                .finalPaymentAmount(EMPTY_BIG_DECIMAL)
                .build();
    }
}
