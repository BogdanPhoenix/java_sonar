package org.university.payment_for_utilities.pojo.responses.company;

import jakarta.persistence.MappedSuperclass;
import lombok.*;
import lombok.experimental.SuperBuilder;
import org.university.payment_for_utilities.domains.address.AddressResidence;
import org.university.payment_for_utilities.domains.service_information_institutions.Edrpou;
import org.university.payment_for_utilities.domains.service_information_institutions.Website;
import org.university.payment_for_utilities.pojo.responses.abstract_class.TransliterationResponse;

@Getter
@Setter
@ToString
@SuperBuilder
@MappedSuperclass
@AllArgsConstructor
@EqualsAndHashCode(callSuper = true)
public class CompanyResponse extends TransliterationResponse {
    private AddressResidence address;
    private Edrpou edrpou;
    private Website website;
    private String currentAccount;
}
