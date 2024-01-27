package org.university.payment_for_utilities.repositories.receipt;

import org.springframework.stereotype.Repository;
import org.university.payment_for_utilities.domains.receipt.BlockAccrualAmount;
import org.university.payment_for_utilities.repositories.ReceiptSearcherRepository;

@Repository
public interface BlockAccrualAmountRepository extends ReceiptSearcherRepository<BlockAccrualAmount> {
}
