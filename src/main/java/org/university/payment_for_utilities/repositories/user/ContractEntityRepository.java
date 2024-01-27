package org.university.payment_for_utilities.repositories.user;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import org.university.payment_for_utilities.domains.user.ContractEntity;

import java.util.Optional;

@Repository
public interface ContractEntityRepository extends JpaRepository<ContractEntity, Long> {
    Optional<ContractEntity> findByNumContract(String numContract);
}
