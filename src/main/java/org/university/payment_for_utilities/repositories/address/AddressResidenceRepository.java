package org.university.payment_for_utilities.repositories.address;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import org.university.payment_for_utilities.domains.address.AddressResidence;
import org.university.payment_for_utilities.domains.address.Settlement;

import java.util.Optional;

@Repository
public interface AddressResidenceRepository extends JpaRepository<AddressResidence, Long> {
    Optional<AddressResidence> findBySettlementAndEnNameStreetAndNumHouseAndNumEntrance(Settlement settlement, String enName, String numHouse, String numEntrance);
}
