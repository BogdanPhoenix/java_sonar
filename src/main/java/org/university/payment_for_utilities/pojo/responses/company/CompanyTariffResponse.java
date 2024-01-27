package org.university.payment_for_utilities.pojo.responses.company;

import jakarta.persistence.MappedSuperclass;
import lombok.*;
import lombok.experimental.SuperBuilder;
import org.university.payment_for_utilities.domains.company.Company;
import org.university.payment_for_utilities.domains.company.TypeOffer;
import org.university.payment_for_utilities.pojo.responses.abstract_class.Response;

import java.math.BigDecimal;

@Getter
@Setter
@ToString
@SuperBuilder
@MappedSuperclass
@AllArgsConstructor
@EqualsAndHashCode(callSuper = true)
public class CompanyTariffResponse extends Response {
    private Company company;
    private TypeOffer type;
    private String name;
    private BigDecimal fixedCost;
}
