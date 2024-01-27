package org.university.payment_for_utilities.services.implementations.auxiliary_services;

import lombok.NonNull;
import org.university.payment_for_utilities.domains.abstract_class.ReceiptSearcher;
import org.university.payment_for_utilities.domains.abstract_class.ReceiptSearcher.ReceiptSearcherBuilder;
import org.university.payment_for_utilities.pojo.requests.abstract_class.ReceiptSearcherRequest;
import org.university.payment_for_utilities.pojo.requests.abstract_class.Request;
import org.university.payment_for_utilities.pojo.responses.abstract_class.ReceiptSearcherResponse;
import org.university.payment_for_utilities.pojo.responses.abstract_class.Response;
import org.university.payment_for_utilities.pojo.responses.abstract_class.ReceiptSearcherResponse.ReceiptSearcherResponseBuilder;
import org.university.payment_for_utilities.repositories.ReceiptSearcherRepository;
import org.university.payment_for_utilities.services.implementations.CrudServiceAbstract;

import java.util.Optional;

public abstract class ReceiptSearcherAbstract<T extends ReceiptSearcher, J extends ReceiptSearcherRepository<T>> extends CrudServiceAbstract<T, J> {
    protected ReceiptSearcherAbstract(J repository, String tableName) {
        super(repository, tableName);
    }

    protected void initReceiptSearcherBuilder(@NonNull ReceiptSearcherBuilder<?, ?> builder, @NonNull Response response) {
        super.initEntityBuilder(builder, response);
        var receiptSearcherResponse = (ReceiptSearcherResponse) response;
        builder.receipt(receiptSearcherResponse.getReceipt());
    }

    protected void initResponseBuilder(ReceiptSearcherResponseBuilder<?, ?> builder, @NonNull T entity) {
        super.initResponseBuilder(builder, entity);
        builder.receipt(entity.getReceipt());
    }

    @Override
    protected void updateEntity(@NonNull T entity, @NonNull Request request) {
        var newValue = (ReceiptSearcherRequest) request;

        if(!newValue.getReceipt().isEmpty()) {
            entity.setReceipt(newValue.getReceipt());
        }
    }

    @Override
    protected Optional<T> findEntity(@NonNull Request request) {
        var receiptSearcher = (ReceiptSearcherRequest) request;
        return repository
                .findByReceipt(
                        receiptSearcher.getReceipt()
                );
    }
}
