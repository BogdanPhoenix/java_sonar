package org.university.payment_for_utilities.repositories.receipt;

import org.springframework.stereotype.Repository;
import org.university.payment_for_utilities.domains.receipt.PaymentHistory;
import org.university.payment_for_utilities.repositories.CounterSearcherRepository;

@Repository
public interface PaymentHistoryRepository extends CounterSearcherRepository<PaymentHistory> {
}
