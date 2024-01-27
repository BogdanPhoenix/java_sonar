package org.university.payment_for_utilities.pojo.requests.user;

import jakarta.persistence.MappedSuperclass;
import lombok.*;
import lombok.experimental.SuperBuilder;
import org.jetbrains.annotations.Contract;
import org.university.payment_for_utilities.domains.company.CompanyTariff;
import org.university.payment_for_utilities.domains.user.RegisteredUser;
import org.university.payment_for_utilities.pojo.requests.abstract_class.Request;

@Getter
@Setter
@ToString
@SuperBuilder
@MappedSuperclass
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(callSuper = false)
public class ContractEntityRequest extends Request {
    private RegisteredUser registeredUser;
    private CompanyTariff companyTariff;
    private String numContract;

    @Override
    public boolean isEmpty() {
        return registeredUser.isEmpty() ||
                companyTariff.isEmpty() ||
                numContract.isBlank();
    }

    @Contract(" -> new")
    public static @NonNull ContractEntityRequest empty() {
        return ContractEntityRequest
                .builder()
                .registeredUser(RegisteredUser.empty())
                .companyTariff(CompanyTariff.empty())
                .numContract("")
                .build();
    }
}
