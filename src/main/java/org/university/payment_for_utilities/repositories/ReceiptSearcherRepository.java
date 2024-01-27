package org.university.payment_for_utilities.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.NoRepositoryBean;
import org.university.payment_for_utilities.domains.receipt.Receipt;

import java.util.Optional;

@NoRepositoryBean
public interface ReceiptSearcherRepository<T> extends JpaRepository<T, Long> {
    Optional<T> findByReceipt(Receipt receipt);
}
