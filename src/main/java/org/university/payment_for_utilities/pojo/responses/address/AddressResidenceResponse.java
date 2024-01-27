package org.university.payment_for_utilities.pojo.responses.address;

import jakarta.persistence.MappedSuperclass;
import lombok.*;
import lombok.experimental.SuperBuilder;
import org.university.payment_for_utilities.domains.address.Settlement;
import org.university.payment_for_utilities.pojo.responses.abstract_class.Response;

@Getter
@Setter
@ToString
@SuperBuilder
@MappedSuperclass
@AllArgsConstructor
@EqualsAndHashCode(callSuper = false)
public class AddressResidenceResponse extends Response {
    private Settlement settlement;
    private String uaNameStreet;
    private String enNameStreet;
    private String numHouse;
    private String numEntrance;
    private String numApartment;
}
