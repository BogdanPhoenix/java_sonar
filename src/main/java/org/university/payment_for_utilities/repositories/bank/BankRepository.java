package org.university.payment_for_utilities.repositories.bank;

import org.springframework.stereotype.Repository;
import org.university.payment_for_utilities.domains.bank.Bank;
import org.university.payment_for_utilities.repositories.TableSearcherRepository;

import java.util.Optional;

@Repository
public interface BankRepository extends TableSearcherRepository<Bank> {
    Optional<Bank> findByMfo(String mfo);
}
