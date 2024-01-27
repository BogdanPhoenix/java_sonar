package org.university.payment_for_utilities.services.implementations.auxiliary_services;

import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.university.payment_for_utilities.domains.abstract_class.TransliterationProperty;
import org.university.payment_for_utilities.pojo.requests.abstract_class.Request;
import org.university.payment_for_utilities.pojo.requests.abstract_class.TransliterationRequest;
import org.university.payment_for_utilities.exceptions.InvalidInputDataException;
import org.university.payment_for_utilities.pojo.responses.abstract_class.Response;
import org.university.payment_for_utilities.pojo.responses.abstract_class.TransliterationResponse;
import org.university.payment_for_utilities.repositories.TableSearcherRepository;
import org.university.payment_for_utilities.domains.abstract_class.TransliterationProperty.TransliterationPropertyBuilder;
import org.university.payment_for_utilities.pojo.responses.abstract_class.TransliterationResponse.TransliterationResponseBuilder;
import org.university.payment_for_utilities.services.implementations.CrudServiceAbstract;

import java.util.Optional;

@Slf4j
public abstract class TransliterationService<T extends TransliterationProperty, J extends TableSearcherRepository<T>> extends CrudServiceAbstract<T, J> {
    protected TransliterationService(J repository, String tableName) {
        super(repository, tableName);
    }

    protected void initTransliterationPropertyBuilder(@NonNull TransliterationPropertyBuilder<?,?> builder, @NonNull Request request) {
        var transliterationRequest = (TransliterationRequest) request;
        builder
                .uaName(transliterationRequest.getUaName())
                .enName(transliterationRequest.getEnName());
    }

    protected void initTransliterationPropertyBuilder(@NonNull TransliterationPropertyBuilder<?,?> builder, @NonNull Response response) {
        super.initEntityBuilder(builder, response);

        var transliterationResponse = (TransliterationResponse) response;
        builder
                .uaName(transliterationResponse.getUaName())
                .enName(transliterationResponse.getEnName());
    }

    protected void initResponseBuilder(@NonNull TransliterationResponseBuilder<?, ?> builder, @NonNull T entity) {
        super.initResponseBuilder(builder, entity);
        builder
                .uaName(entity.getUaName())
                .enName(entity.getEnName());
    }

    @Override
    protected void updateEntity(@NonNull T entity, @NonNull Request request) {
        var newValue = (TransliterationRequest) request;

        if(!newValue.getUaName().isBlank()){
            entity.setUaName(newValue.getUaName());
        }
        if(!newValue.getEnName().isBlank()){
            entity.setEnName(newValue.getEnName());
        }
    }

    @Override
    protected void validationProcedureRequest(@NonNull Request request) throws InvalidInputDataException {
        var transliterationRequest = (TransliterationRequest) request;

        validateName(transliterationRequest.getUaName());
        validateName(transliterationRequest.getEnName());
    }

    @Override
    protected Optional<T> findEntity(@NonNull Request request) {
        var transliterationRequest = (TransliterationRequest) request;
        return repository
                .findByEnName(
                        transliterationRequest.getEnName()
                );
    }
}
