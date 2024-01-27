package org.university.payment_for_utilities.repositories.company;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import org.university.payment_for_utilities.domains.company.Company;
import org.university.payment_for_utilities.domains.company.CompanyTariff;

import java.util.Optional;

@Repository
public interface CompanyTariffRepository extends JpaRepository<CompanyTariff, Long> {
    Optional<CompanyTariff> findByCompanyAndName(Company company, String name);
}
