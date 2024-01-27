package org.university.payment_for_utilities.services.implementations.address;

import lombok.NonNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.university.payment_for_utilities.domains.address.Settlement;
import org.university.payment_for_utilities.pojo.requests.address.SettlementRequest;
import org.university.payment_for_utilities.pojo.requests.abstract_class.Request;
import org.university.payment_for_utilities.pojo.responses.address.SettlementResponse;
import org.university.payment_for_utilities.pojo.responses.abstract_class.Response;
import org.university.payment_for_utilities.exceptions.DuplicateException;
import org.university.payment_for_utilities.exceptions.EmptyRequestException;
import org.university.payment_for_utilities.exceptions.InvalidInputDataException;
import org.university.payment_for_utilities.repositories.address.SettlementRepository;
import org.university.payment_for_utilities.services.implementations.CrudServiceAbstract;
import org.university.payment_for_utilities.services.interfaces.address.AddressResidenceService;
import org.university.payment_for_utilities.services.interfaces.address.SettlementService;

import java.util.Optional;

import static org.university.payment_for_utilities.services.implementations.tools.ExceptionTools.throwRuntimeException;

@Service
public class SettlementServiceImpl extends CrudServiceAbstract<Settlement, SettlementRepository> implements SettlementService {
    private static final String INDEX_TEMPLATE = "^\\d{5}$";
    private final AddressResidenceService addressResidenceService;

    @Autowired
    public SettlementServiceImpl(
            SettlementRepository repository,
            AddressResidenceService addressResidenceService
    ) {
        super(repository, "Settlements");
        this.addressResidenceService = addressResidenceService;
    }


    @Override
    protected Settlement createEntity(Request request) {
        var settlementRequest = (SettlementRequest) request;
        return Settlement
                .builder()
                .type(settlementRequest.getType())
                .zipCode(settlementRequest.getZipCode())
                .name(settlementRequest.getName())
                .build();
    }

    @Override
    protected Settlement createEntity(Response response) {
        var settlementResponse = (SettlementResponse) response;
        var builder = Settlement.builder();
        initEntityBuilder(builder, response);

        return builder
                .type(settlementResponse.getType())
                .zipCode(settlementResponse.getZipCode())
                .name(settlementResponse.getName())
                .build();
    }

    @Override
    protected Response createResponse(@NonNull Settlement entity) {
        var builder = SettlementResponse.builder();
        initResponseBuilder(builder, entity);

        return builder
                .type(entity.getType())
                .zipCode(entity.getZipCode())
                .name(entity.getName())
                .build();
    }

    @Override
    protected void deactivatedChildren(@NonNull Settlement entity) {
        deactivateChildrenCollection(entity.getAddresses(), addressResidenceService);
    }

    @Override
    protected void updateEntity(@NonNull Settlement entity, @NonNull Request request) {
        var newValue = (SettlementRequest) request;

        if(!newValue.getType().isEmpty()){
            entity.setType(newValue.getType());
        }
        if(!newValue.getZipCode().isBlank()){
            entity.setZipCode(newValue.getZipCode());
        }
        if(!newValue.getName().isEmpty()){
            entity.setName(newValue.getName());
        }
    }

    @Override
    protected void validationProcedureRequest(@NonNull Request request) throws EmptyRequestException, InvalidInputDataException, DuplicateException {
        var settlementRequest = (SettlementRequest) request;
        validateZipCode(settlementRequest.getZipCode());
    }

    private void validateZipCode(@NonNull String zipCode) throws InvalidInputDataException{
        if(isValidIndex(zipCode)){
            return;
        }

        var message = String.format("You entered an incorrect zip code: \"%s\". The area code must consist of only numbers and be five characters long.", zipCode);
        throwRuntimeException(message, InvalidInputDataException::new);
    }

    private boolean isValidIndex(@NonNull String zipCode) {
        return zipCode.isBlank() || zipCode
                .matches(INDEX_TEMPLATE);
    }

    @Override
    protected Optional<Settlement> findEntity(@NonNull Request request) {
        var settlementRequest = (SettlementRequest) request;
        return repository
                .findByZipCode(
                        settlementRequest.getZipCode()
                );
    }
}
