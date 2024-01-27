package org.university.payment_for_utilities.pojo.requests.bank;

import jakarta.persistence.MappedSuperclass;
import lombok.*;
import lombok.experimental.SuperBuilder;
import org.jetbrains.annotations.Contract;
import org.university.payment_for_utilities.domains.bank.Bank;
import org.university.payment_for_utilities.domains.service_information_institutions.PhoneNum;
import org.university.payment_for_utilities.pojo.requests.abstract_class.Request;

@Getter
@Setter
@ToString
@SuperBuilder
@MappedSuperclass
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(callSuper = false)
public class BankPhoneNumRequest extends Request {
    private Bank bank;
    private PhoneNum phoneNum;

    @Override
    public boolean isEmpty() {
        return this.bank.isEmpty() ||
                this.phoneNum.isEmpty();
    }

    @Contract(" -> new")
    public static @NonNull BankPhoneNumRequest empty(){
        return BankPhoneNumRequest
                .builder()
                .bank(Bank.empty())
                .phoneNum(PhoneNum.empty())
                .build();
    }
}
