package org.university.payment_for_utilities.pojo.requests.company;

import jakarta.persistence.MappedSuperclass;
import lombok.*;
import lombok.experimental.SuperBuilder;
import org.jetbrains.annotations.Contract;
import org.university.payment_for_utilities.domains.address.AddressResidence;
import org.university.payment_for_utilities.domains.service_information_institutions.Edrpou;
import org.university.payment_for_utilities.domains.service_information_institutions.Website;
import org.university.payment_for_utilities.pojo.requests.abstract_class.TransliterationRequest;

@Getter
@Setter
@ToString
@SuperBuilder
@MappedSuperclass
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(callSuper = false)
public class CompanyRequest extends TransliterationRequest {
    private AddressResidence address;
    private Edrpou edrpou;
    private Website website;
    private String currentAccount;

    @Override
    public boolean isEmpty() {
        return super.isEmpty() ||
                address.isEmpty() ||
                edrpou.isEmpty() ||
                website.isEmpty() ||
                currentAccount.isBlank();
    }

    @Contract(" -> new")
    public static @NonNull CompanyRequest empty(){
        var entity = (CompanyRequest) initEmpty(CompanyRequest.builder());

        entity.setAddress(AddressResidence.empty());
        entity.setWebsite(Website.empty());
        entity.setEdrpou(Edrpou.empty());
        entity.setCurrentAccount("");

        return entity;
    }
}
