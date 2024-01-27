package org.university.payment_for_utilities.repositories.bank;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import org.university.payment_for_utilities.domains.bank.Bank;
import org.university.payment_for_utilities.domains.bank.BankPhoneNum;
import org.university.payment_for_utilities.domains.service_information_institutions.PhoneNum;

import java.util.Optional;

@Repository
public interface BankPhoneNumRepository extends JpaRepository<BankPhoneNum, Long> {
    Optional<BankPhoneNum> findByBankAndPhoneNum(Bank bank, PhoneNum phone);
}
