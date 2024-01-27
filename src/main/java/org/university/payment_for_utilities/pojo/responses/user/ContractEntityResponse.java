package org.university.payment_for_utilities.pojo.responses.user;

import jakarta.persistence.MappedSuperclass;
import lombok.*;
import lombok.experimental.SuperBuilder;
import org.university.payment_for_utilities.domains.company.CompanyTariff;
import org.university.payment_for_utilities.domains.user.RegisteredUser;
import org.university.payment_for_utilities.pojo.responses.abstract_class.Response;

@Getter
@Setter
@ToString
@SuperBuilder
@MappedSuperclass
@AllArgsConstructor
@EqualsAndHashCode(callSuper = true)
public class ContractEntityResponse extends Response {
    private RegisteredUser registeredUser;
    private CompanyTariff companyTariff;
    private String numContract;
}
