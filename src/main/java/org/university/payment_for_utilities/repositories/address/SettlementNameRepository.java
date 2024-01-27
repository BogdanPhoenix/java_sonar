package org.university.payment_for_utilities.repositories.address;

import org.springframework.stereotype.Repository;
import org.university.payment_for_utilities.domains.address.SettlementName;
import org.university.payment_for_utilities.repositories.TableSearcherRepository;

@Repository
public interface SettlementNameRepository extends TableSearcherRepository<SettlementName> {
}
