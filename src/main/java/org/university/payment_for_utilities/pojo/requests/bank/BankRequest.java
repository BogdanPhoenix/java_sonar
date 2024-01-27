package org.university.payment_for_utilities.pojo.requests.bank;

import jakarta.persistence.MappedSuperclass;
import lombok.*;
import lombok.experimental.SuperBuilder;
import org.jetbrains.annotations.Contract;
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
public class BankRequest extends TransliterationRequest {
    private Website website;
    private Edrpou edrpou;
    private String mfo;

    @Override
    public boolean isEmpty() {
        return super.isEmpty() ||
                website.isEmpty() ||
                edrpou.isEmpty() ||
                mfo.isBlank();
    }

    @Contract(" -> new")
    public static @NonNull BankRequest empty(){
        var entity = (BankRequest) initEmpty(BankRequest.builder());

        entity.setWebsite(Website.empty());
        entity.setEdrpou(Edrpou.empty());
        entity.setMfo("");

        return entity;
    }
}
