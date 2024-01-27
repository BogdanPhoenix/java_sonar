package org.university.payment_for_utilities.repositories.service_information_institutions;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import org.university.payment_for_utilities.domains.service_information_institutions.Edrpou;

import java.util.Optional;

@Repository
public interface EdrpouRepository extends JpaRepository<Edrpou, Long> {
    Optional<Edrpou> findByValue(String value);
}
