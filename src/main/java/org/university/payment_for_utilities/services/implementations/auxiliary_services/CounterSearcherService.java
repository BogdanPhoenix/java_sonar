package org.university.payment_for_utilities.services.implementations.auxiliary_services;

import lombok.NonNull;
import org.university.payment_for_utilities.domains.abstract_class.CounterSearcher;
import org.university.payment_for_utilities.domains.abstract_class.CounterSearcher.CounterSearcherBuilder;
import org.university.payment_for_utilities.exceptions.InvalidInputDataException;
import org.university.payment_for_utilities.pojo.requests.abstract_class.CounterSearcherRequest;
import org.university.payment_for_utilities.pojo.requests.abstract_class.Request;
import org.university.payment_for_utilities.pojo.responses.abstract_class.CounterSearcherResponse;
import org.university.payment_for_utilities.pojo.responses.abstract_class.Response;
import org.university.payment_for_utilities.repositories.CounterSearcherRepository;
import org.university.payment_for_utilities.pojo.responses.abstract_class.CounterSearcherResponse.CounterSearcherResponseBuilder;

import static org.university.payment_for_utilities.domains.abstract_class.CounterSearcher.EMPTY_COUNTER;
import static org.university.payment_for_utilities.services.implementations.tools.CounterTools.validatePrevValueCounter;

public abstract class CounterSearcherService<T extends CounterSearcher, J extends CounterSearcherRepository<T>> extends ReceiptSearcherAbstract<T, J> {
    protected CounterSearcherService(J repository, String tableName) {
        super(repository, tableName);
    }

    protected void initCounterSearcherBuilder(@NonNull CounterSearcherBuilder<?, ?> builder, @NonNull Response response) {
        super.initReceiptSearcherBuilder(builder, response);
        var counterResponse = (CounterSearcherResponse) response;

        builder
                .prevValueCounter(counterResponse.getPrevValueCounter())
                .currentValueCounter(counterResponse.getCurrentValueCounter());
    }

    protected void initCounterResponseBuilder(CounterSearcherResponseBuilder<?, ?> builder, @NonNull T entity) {
        super.initResponseBuilder(builder, entity);
        builder
                .prevValueCounter(entity.getPrevValueCounter())
                .currentValueCounter(entity.getCurrentValueCounter());
    }

    @Override
    protected void updateEntity(@NonNull T entity, @NonNull Request request) {
        super.updateEntity(entity, request);
        var newValue = (CounterSearcherRequest) request;

        if(!newValue.getPrevValueCounter().equals(EMPTY_COUNTER)){
            entity.setPrevValueCounter(newValue.getPrevValueCounter());
        }
        if(!newValue.getCurrentValueCounter().equals(EMPTY_COUNTER)){
            entity.setCurrentValueCounter(newValue.getCurrentValueCounter());
        }
    }

    @Override
    protected void validationProcedureRequest(@NonNull Request request) throws InvalidInputDataException {
        var counterRequest = (CounterSearcherRequest) request;
        validatePrevValueCounter(counterRequest);
    }
}
