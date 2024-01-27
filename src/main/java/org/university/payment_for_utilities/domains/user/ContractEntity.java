package org.university.payment_for_utilities.domains.user;

import jakarta.persistence.*;
import lombok.*;
import lombok.experimental.SuperBuilder;
import org.hibernate.annotations.DynamicInsert;
import org.hibernate.annotations.DynamicUpdate;
import org.jetbrains.annotations.Contract;
import org.university.payment_for_utilities.domains.abstract_class.TableInfo;
import org.university.payment_for_utilities.domains.company.CompanyTariff;
import org.university.payment_for_utilities.domains.receipt.Receipt;

import java.util.List;

import static jakarta.persistence.CascadeType.*;
import static jakarta.persistence.CascadeType.DETACH;

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
@Table(name = "contract_entities")
public class ContractEntity extends TableInfo {
    @ManyToOne
    @JoinColumn(name = "id_registered_user", nullable = false)
    @NonNull
    private RegisteredUser registeredUser;

    @ManyToOne
    @JoinColumn(name = "id_company_tariff", nullable = false)
    @NonNull
    private CompanyTariff companyTariff;

    @Column(name = "num_contract", length = 11, nullable = false, unique = true)
    @NonNull
    private String numContract;

    @ToString.Exclude
    @EqualsAndHashCode.Exclude
    @OneToMany(mappedBy = "contractEntity", cascade={MERGE, REMOVE, REFRESH, DETACH}, fetch = FetchType.LAZY)
    private List<Receipt> receipts;

    @Override
    public boolean isEmpty() {
        return registeredUser.isEmpty() ||
                companyTariff.isEmpty() ||
                numContract.isBlank();
    }

    @Contract(" -> new")
    public static @NonNull ContractEntity empty() {
        var builder = builder();
        TableInfo.initEmpty(builder);

        return builder
                .registeredUser(RegisteredUser.empty())
                .companyTariff(CompanyTariff.empty())
                .numContract("")
                .build();
    }
}
