package org.university.payment_for_utilities.pojo.requests.company;

import jakarta.persistence.MappedSuperclass;
import lombok.*;
import lombok.experimental.SuperBuilder;
import org.jetbrains.annotations.Contract;
import org.university.payment_for_utilities.domains.company.Company;
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
public class CompanyPhoneNumRequest extends Request {
    private Company company;
    private PhoneNum phoneNum;

    @Override
    public boolean isEmpty() {
        return this.company.isEmpty() ||
                this.phoneNum.isEmpty();
    }

    @Contract(" -> new")
    public static @NonNull CompanyPhoneNumRequest empty(){
        return CompanyPhoneNumRequest
                .builder()
                .company(Company.empty())
                .phoneNum(PhoneNum.empty())
                .build();
    }
}
