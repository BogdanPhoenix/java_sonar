package org.university.payment_for_utilities.services.implementations.user;

import lombok.NonNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.university.payment_for_utilities.domains.user.ContractEntity;
import org.university.payment_for_utilities.exceptions.InvalidInputDataException;
import org.university.payment_for_utilities.pojo.requests.abstract_class.Request;
import org.university.payment_for_utilities.pojo.requests.user.ContractEntityRequest;
import org.university.payment_for_utilities.pojo.responses.abstract_class.Response;
import org.university.payment_for_utilities.pojo.responses.user.ContractEntityResponse;
import org.university.payment_for_utilities.repositories.user.ContractEntityRepository;
import org.university.payment_for_utilities.services.implementations.CrudServiceAbstract;
import org.university.payment_for_utilities.services.interfaces.receipt.ReceiptService;
import org.university.payment_for_utilities.services.interfaces.user.ContractEntityService;

import java.util.Optional;

import static org.university.payment_for_utilities.services.implementations.tools.ExceptionTools.throwRuntimeException;

@Service
public class ContractEntityServiceImpl extends CrudServiceAbstract<ContractEntity, ContractEntityRepository> implements ContractEntityService {
    private static final String NUM_CONTRACT_TEMPLATE = "^\\d{11}$";

    private final ReceiptService receiptService;

    @Autowired
    public ContractEntityServiceImpl(
            ContractEntityRepository repository,
            ReceiptService receiptService
    ) {
        super(repository, "Contract entities");
        this.receiptService = receiptService;
    }

    @Override
    protected ContractEntity createEntity(Request request) {
        var contractRequest = (ContractEntityRequest) request;
        return ContractEntity
                .builder()
                .registeredUser(contractRequest.getRegisteredUser())
                .companyTariff(contractRequest.getCompanyTariff())
                .numContract(contractRequest.getNumContract())
                .build();
    }

    @Override
    protected ContractEntity createEntity(Response response) {
        var contractResponse = (ContractEntityResponse) response;
        var builder = ContractEntity.builder();
        initEntityBuilder(builder, response);

        return builder
                .registeredUser(contractResponse.getRegisteredUser())
                .companyTariff(contractResponse.getCompanyTariff())
                .numContract(contractResponse.getNumContract())
                .build();
    }

    @Override
    protected Response createResponse(ContractEntity entity) {
        var builder = ContractEntityResponse.builder();
        initResponseBuilder(builder, entity);

        return builder
                .registeredUser(entity.getRegisteredUser())
                .companyTariff(entity.getCompanyTariff())
                .numContract(entity.getNumContract())
                .build();
    }

    @Override
    protected void deactivatedChildren(@NonNull ContractEntity entity) {
        deactivateChildrenCollection(entity.getReceipts(), receiptService);
    }

    @Override
    protected void updateEntity(@NonNull ContractEntity entity, @NonNull Request request) {
        var newValue = (ContractEntityRequest) request;

        if(!newValue.getRegisteredUser().isEmpty()){
            entity.setRegisteredUser(newValue.getRegisteredUser());
        }
        if(!newValue.getCompanyTariff().isEmpty()){
            entity.setCompanyTariff(newValue.getCompanyTariff());
        }
        if(!newValue.getNumContract().isBlank()){
            entity.setNumContract(newValue.getNumContract());
        }
    }

    @Override
    protected void validationProcedureRequest(@NonNull Request request) throws InvalidInputDataException {
        var contractRequest = (ContractEntityRequest) request;
        validateNumContract(contractRequest.getNumContract());
    }

    private void validateNumContract(@NonNull String numContract) throws InvalidInputDataException {
        if(isNumContract(numContract)){
            return;
        }

        var message = String.format("Contract number: \"%s\" has not been validated. It should contain only eleven digits.", numContract);
        throwRuntimeException(message, InvalidInputDataException::new);
    }

    private boolean isNumContract(@NonNull String numContract){
        return numContract.isBlank() || numContract
                .matches(NUM_CONTRACT_TEMPLATE);
    }

    @Override
    protected Optional<ContractEntity> findEntity(@NonNull Request request) {
        var contractRequest = (ContractEntityRequest) request;
        return repository
                .findByNumContract(
                        contractRequest.getNumContract()
                );
    }
}
