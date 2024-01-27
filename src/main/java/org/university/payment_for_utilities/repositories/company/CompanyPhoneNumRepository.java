package org.university.payment_for_utilities.repositories.company;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import org.university.payment_for_utilities.domains.company.Company;
import org.university.payment_for_utilities.domains.company.CompanyPhoneNum;
import org.university.payment_for_utilities.domains.service_information_institutions.PhoneNum;

import java.util.Optional;

@Repository
public interface CompanyPhoneNumRepository extends JpaRepository<CompanyPhoneNum, Long> {
    Optional<CompanyPhoneNum> findByCompanyAndPhoneNum(Company company, PhoneNum phoneNum);
}
