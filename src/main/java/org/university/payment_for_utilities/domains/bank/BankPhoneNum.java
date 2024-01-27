package org.university.payment_for_utilities.domains.bank;

import jakarta.persistence.*;
import lombok.*;
import lombok.experimental.SuperBuilder;
import org.hibernate.annotations.DynamicInsert;
import org.hibernate.annotations.DynamicUpdate;
import org.jetbrains.annotations.Contract;
import org.university.payment_for_utilities.domains.abstract_class.TableInfo;
import org.university.payment_for_utilities.domains.service_information_institutions.PhoneNum;

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
@Table(name = "bank_phone_nums")
public class BankPhoneNum extends TableInfo {
    @ManyToOne
    @JoinColumn(name = "id_bank", nullable = false)
    @NonNull
    private Bank bank;

    @OneToOne(cascade={MERGE, REMOVE, REFRESH, DETACH})
    @JoinColumn(name = "id_phone_num", nullable = false, unique = true)
    @NonNull
    private PhoneNum phoneNum;

    @Override
    public boolean isEmpty() {
        return bank.isEmpty() ||
                phoneNum.isEmpty();
    }

    @Contract(" -> new")
    public static @NonNull BankPhoneNum empty(){
        var builder = builder();
        TableInfo.initEmpty(builder);

        return builder
                .bank(Bank.empty())
                .phoneNum(PhoneNum.empty())
                .build();
    }
}
