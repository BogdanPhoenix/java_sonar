package org.university.payment_for_utilities.domains.receipt;

import jakarta.persistence.*;
import lombok.*;
import lombok.experimental.SuperBuilder;
import org.hibernate.annotations.DynamicInsert;
import org.hibernate.annotations.DynamicUpdate;
import org.jetbrains.annotations.Contract;
import org.university.payment_for_utilities.domains.abstract_class.TableInfo;
import org.university.payment_for_utilities.domains.user.ContractEntity;
import org.university.payment_for_utilities.domains.bank.Bank;

import java.time.LocalDate;
import java.util.List;

import static jakarta.persistence.CascadeType.*;

@Entity
@Getter
@Setter
@ToString
@SuperBuilder
@DynamicUpdate
@DynamicInsert
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(callSuper = false)
@Table(name = "receipts",
    uniqueConstraints = @UniqueConstraint(columnNames = {"id_contract", "id_bank", "bill_month"})
)
public class Receipt extends TableInfo {
    @ManyToOne
    @JoinColumn(name = "id_contract", nullable = false)
    @NonNull
    private ContractEntity contractEntity;

    @ManyToOne
    @JoinColumn(name = "id_bank", nullable = false)
    @NonNull
    private Bank bank;

    @Column(name = "bill_month", nullable = false)
    @NonNull
    private LocalDate billMonth;

    @ToString.Exclude
    @EqualsAndHashCode.Exclude
    @OneToMany(mappedBy = "receipt", cascade={MERGE, REMOVE, REFRESH, DETACH}, fetch = FetchType.LAZY)
    private List<PaymentHistory> paymentHistories;

    @ToString.Exclude
    @EqualsAndHashCode.Exclude
    @OneToMany(mappedBy = "receipt", cascade={MERGE, REMOVE, REFRESH, DETACH}, fetch = FetchType.LAZY)
    private List<BlockAccrualAmount> blockAccrualAmounts;

    @ToString.Exclude
    @EqualsAndHashCode.Exclude
    @OneToMany(mappedBy = "receipt", cascade={MERGE, REMOVE, REFRESH, DETACH}, fetch = FetchType.LAZY)
    private List<BlockMeterReading> blockMeterReadings;

    @Override
    public boolean isEmpty() {
        return contractEntity.isEmpty() ||
                bank.isEmpty() ||
                billMonth == LocalDate.MIN;
    }

    @Contract(" -> new")
    public static @NonNull Receipt empty() {
        var builder = builder();
        TableInfo.initEmpty(builder);

        return builder
                .contractEntity(ContractEntity.empty())
                .bank(Bank.empty())
                .billMonth(LocalDate.MIN)
                .build();
    }
}
