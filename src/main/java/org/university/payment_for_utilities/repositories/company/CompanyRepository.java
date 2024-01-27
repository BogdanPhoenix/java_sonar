package org.university.payment_for_utilities.repositories.company;

import org.springframework.stereotype.Repository;
import org.university.payment_for_utilities.domains.company.Company;
import org.university.payment_for_utilities.repositories.TableSearcherRepository;

import java.util.Optional;

@Repository
public interface CompanyRepository extends TableSearcherRepository<Company> {
    Optional<Company> findByCurrentAccount(String currentAccount);
}
