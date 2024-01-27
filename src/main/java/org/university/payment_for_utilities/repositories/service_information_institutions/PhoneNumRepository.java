package org.university.payment_for_utilities.repositories.service_information_institutions;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import org.university.payment_for_utilities.domains.service_information_institutions.PhoneNum;

import java.util.Optional;

@Repository
public interface PhoneNumRepository extends JpaRepository<PhoneNum, Long> {
    Optional<PhoneNum> findByNumber(String number);
}
