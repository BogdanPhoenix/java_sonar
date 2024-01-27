package org.university.payment_for_utilities.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.NoRepositoryBean;

import java.util.Optional;

@NoRepositoryBean
public interface TableSearcherRepository<T> extends JpaRepository<T, Long> {
    Optional<T> findByEnName(String name);
}
