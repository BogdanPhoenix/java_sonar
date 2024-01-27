package org.university.payment_for_utilities.pojo.responses.receipt;

import jakarta.persistence.MappedSuperclass;
import lombok.*;
import lombok.experimental.SuperBuilder;
import org.university.payment_for_utilities.pojo.responses.abstract_class.ReceiptSearcherResponse;

import java.math.BigDecimal;

@Getter
@Setter
@ToString
@SuperBuilder
@MappedSuperclass
@AllArgsConstructor
@EqualsAndHashCode(callSuper = true)
public class BlockAccrualAmountResponse extends ReceiptSearcherResponse {
    private BigDecimal debtBeginMonth;
    private BigDecimal debtEndMonth;
    private BigDecimal fine;
    private BigDecimal lastCreditedPayment;
    private BigDecimal amountDue;
}
