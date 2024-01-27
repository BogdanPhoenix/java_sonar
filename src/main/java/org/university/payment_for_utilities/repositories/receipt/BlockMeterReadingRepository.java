package org.university.payment_for_utilities.repositories.receipt;

import org.springframework.stereotype.Repository;
import org.university.payment_for_utilities.domains.receipt.BlockMeterReading;
import org.university.payment_for_utilities.repositories.CounterSearcherRepository;

@Repository
public interface BlockMeterReadingRepository extends CounterSearcherRepository<BlockMeterReading> {

}
