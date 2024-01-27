package org.university.payment_for_utilities.repositories;

import org.springframework.data.repository.NoRepositoryBean;

@NoRepositoryBean
public interface CounterSearcherRepository<T> extends ReceiptSearcherRepository<T>{
}
