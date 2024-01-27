package org.university.payment_for_utilities.services.implementations.auxiliary_services;

import lombok.NonNull;
import org.springframework.data.jpa.repository.JpaRepository;
import org.university.payment_for_utilities.domains.abstract_class.TableInfo;
import org.university.payment_for_utilities.exceptions.InvalidInputDataException;
import org.university.payment_for_utilities.pojo.requests.abstract_class.Request;
import org.university.payment_for_utilities.services.implementations.CrudServiceAbstract;

public abstract class WorkingWithPhoneNumAbstract<T extends TableInfo, J extends JpaRepository<T, Long>> extends CrudServiceAbstract<T, J> {
    protected WorkingWithPhoneNumAbstract(J repository, String tableName) {
        super(repository, tableName);
    }

    @Override
    protected void validationProcedureRequest(@NonNull Request request) throws InvalidInputDataException {
        // TODO No additional validation methods are required. It is enough to check for an empty query
        //  during insertion and duplication during insertion and update of data.
    }
}
