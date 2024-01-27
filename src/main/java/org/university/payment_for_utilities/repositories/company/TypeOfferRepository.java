package org.university.payment_for_utilities.repositories.company;

import org.springframework.stereotype.Repository;
import org.university.payment_for_utilities.domains.company.TypeOffer;
import org.university.payment_for_utilities.domains.service_information_institutions.UnitMeasurement;
import org.university.payment_for_utilities.repositories.TableSearcherRepository;

import java.util.Optional;

@Repository
public interface TypeOfferRepository extends TableSearcherRepository<TypeOffer> {
    Optional<TypeOffer> findByUnitMeasurementAndEnName(UnitMeasurement unit, String enName);
}
