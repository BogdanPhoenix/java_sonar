package org.university.payment_for_utilities.pojo.requests.receipt;

import jakarta.persistence.MappedSuperclass;
import lombok.*;
import lombok.experimental.SuperBuilder;
import org.jetbrains.annotations.Contract;
import org.university.payment_for_utilities.domains.bank.Bank;
import org.university.payment_for_utilities.domains.user.ContractEntity;
import org.university.payment_for_utilities.pojo.requests.abstract_class.Request;

import java.time.LocalDate;

@Getter
@Setter
@ToString
@SuperBuilder
@MappedSuperclass
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(callSuper = false)
public class ReceiptRequest extends Request {
    private ContractEntity contractEntity;
    private Bank bank;
    private LocalDate billMonth;

    @Override
    public boolean isEmpty() {
        return contractEntity.isEmpty() ||
                bank.isEmpty() ||
                billMonth == LocalDate.MIN;
    }

    @Contract(" -> new")
    public static @NonNull ReceiptRequest empty() {
        return ReceiptRequest
                .builder()
                .contractEntity(ContractEntity.empty())
                .bank(Bank.empty())
                .billMonth(LocalDate.MIN)
                .build();
    }
}
