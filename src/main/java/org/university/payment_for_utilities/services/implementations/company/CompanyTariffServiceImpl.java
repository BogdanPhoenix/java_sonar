package org.university.payment_for_utilities.services.implementations.company;

import lombok.NonNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.university.payment_for_utilities.domains.company.CompanyTariff;
import org.university.payment_for_utilities.exceptions.InvalidInputDataException;
import org.university.payment_for_utilities.pojo.requests.abstract_class.Request;
import org.university.payment_for_utilities.pojo.requests.company.CompanyTariffRequest;
import org.university.payment_for_utilities.pojo.responses.abstract_class.Response;
import org.university.payment_for_utilities.pojo.responses.company.CompanyTariffResponse;
import org.university.payment_for_utilities.repositories.company.CompanyTariffRepository;
import org.university.payment_for_utilities.services.implementations.CrudServiceAbstract;
import org.university.payment_for_utilities.services.interfaces.company.CompanyTariffService;
import org.university.payment_for_utilities.services.interfaces.user.ContractEntityService;

import java.util.Optional;

import static org.university.payment_for_utilities.services.implementations.tools.FinanceTools.convertStringToBigDecimal;
import static org.university.payment_for_utilities.services.implementations.tools.FinanceTools.validateFinance;

@Service
public class CompanyTariffServiceImpl extends CrudServiceAbstract<CompanyTariff, CompanyTariffRepository> implements CompanyTariffService {
    private final ContractEntityService contractEntityService;

    @Autowired
    public CompanyTariffServiceImpl(
            CompanyTariffRepository repository,
            ContractEntityService contractEntityService
    ) {
        super(repository, "Company tariffs");
        this.contractEntityService = contractEntityService;
    }

    @Override
    protected CompanyTariff createEntity(Request request) {
        var companyTariffRequest = (CompanyTariffRequest) request;
        var fixedCost = convertStringToBigDecimal(companyTariffRequest.getFixedCost());

        return CompanyTariff
                .builder()
                .company(companyTariffRequest.getCompany())
                .type(companyTariffRequest.getType())
                .name(companyTariffRequest.getName())
                .fixedCost(fixedCost)
                .build();
    }

    @Override
    protected CompanyTariff createEntity(Response response) {
        var companyTariffResponse = (CompanyTariffResponse) response;
        var builder = CompanyTariff.builder();
        initEntityBuilder(builder, response);

        return builder
                .company(companyTariffResponse.getCompany())
                .type(companyTariffResponse.getType())
                .name(companyTariffResponse.getName())
                .fixedCost(companyTariffResponse.getFixedCost())
                .build();
    }

    @Override
    protected Response createResponse(CompanyTariff entity) {
        var builder = CompanyTariffResponse.builder();
        initResponseBuilder(builder, entity);

        return builder
                .company(entity.getCompany())
                .type(entity.getType())
                .name(entity.getName())
                .fixedCost(entity.getFixedCost())
                .build();
    }

    @Override
    protected void deactivatedChildren(@NonNull CompanyTariff entity) {
        deactivateChildrenCollection(entity.getContractEntities(), contractEntityService);
    }

    @Override
    protected void updateEntity(@NonNull CompanyTariff entity, @NonNull Request request) {
        var newValue = (CompanyTariffRequest) request;

        if(!newValue.getCompany().isEmpty()){
            entity.setCompany(newValue.getCompany());
        }
        if(!newValue.getType().isEmpty()){
            entity.setType(newValue.getType());
        }
        if(!newValue.getName().isBlank()){
            entity.setName(newValue.getName());
        }
        if(!newValue.getFixedCost().isBlank()){
            var fixedCost = convertStringToBigDecimal(newValue.getFixedCost());
            entity.setFixedCost(fixedCost);
        }
    }

    @Override
    protected void validationProcedureRequest(@NonNull Request request) throws InvalidInputDataException {
        var companyTariffRequest = (CompanyTariffRequest) request;

        validateName(companyTariffRequest.getName());
        validateFinance("fixed cost", companyTariffRequest.getFixedCost());
    }

    @Override
    protected Optional<CompanyTariff> findEntity(@NonNull Request request) {
        var companyTariffRequest = (CompanyTariffRequest) request;
        return repository
                .findByCompanyAndName(
                        companyTariffRequest.getCompany(),
                        companyTariffRequest.getName()
                );
    }
}
