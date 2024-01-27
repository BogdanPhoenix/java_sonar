package org.university.payment_for_utilities.services.implementations.company;

import lombok.NonNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.university.payment_for_utilities.domains.company.Company;
import org.university.payment_for_utilities.exceptions.InvalidInputDataException;
import org.university.payment_for_utilities.pojo.requests.company.CompanyRequest;
import org.university.payment_for_utilities.pojo.requests.abstract_class.Request;
import org.university.payment_for_utilities.pojo.responses.company.CompanyResponse;
import org.university.payment_for_utilities.pojo.responses.abstract_class.Response;
import org.university.payment_for_utilities.repositories.company.CompanyRepository;
import org.university.payment_for_utilities.services.implementations.auxiliary_services.TransliterationService;
import org.university.payment_for_utilities.services.interfaces.company.CompanyPhoneNumService;
import org.university.payment_for_utilities.services.interfaces.company.CompanyService;
import org.university.payment_for_utilities.services.interfaces.company.CompanyTariffService;
import org.university.payment_for_utilities.services.interfaces.service_information_institutions.EdrpouService;
import org.university.payment_for_utilities.services.interfaces.service_information_institutions.WebsiteService;

import java.util.Optional;

import static org.university.payment_for_utilities.services.implementations.tools.ExceptionTools.throwRuntimeException;

@Service
public class CompanyServiceImpl extends TransliterationService<Company, CompanyRepository> implements CompanyService {
    private static final String CURRENT_ACCOUNT_TEMPLATE = "^\\d{14}$";

    private final EdrpouService edrpouService;
    private final WebsiteService websiteService;
    private final CompanyPhoneNumService companyPhoneNumService;
    private final CompanyTariffService companyTariffService;

    @Autowired
    public CompanyServiceImpl(
            CompanyRepository repository,
            EdrpouService edrpouService,
            WebsiteService websiteService,
            CompanyPhoneNumService companyPhoneNumService,
            CompanyTariffService companyTariffService
    ) {
        super(repository, "Companies");
        this.edrpouService = edrpouService;
        this.websiteService = websiteService;
        this.companyPhoneNumService = companyPhoneNumService;
        this.companyTariffService = companyTariffService;
    }

    @Override
    protected Company createEntity(Request request) {
        var builder = Company.builder();
        super.initTransliterationPropertyBuilder(builder, request);
        var companyRequest = (CompanyRequest) request;

        return builder
                .address(companyRequest.getAddress())
                .edrpou(companyRequest.getEdrpou())
                .website(companyRequest.getWebsite())
                .currentAccount(companyRequest.getCurrentAccount())
                .build();
    }

    @Override
    protected Company createEntity(Response response) {
        var builder = Company.builder();
        var companyResponse = (CompanyResponse) response;
        super.initTransliterationPropertyBuilder(builder, response);

        return builder
                .address(companyResponse.getAddress())
                .edrpou(companyResponse.getEdrpou())
                .website(companyResponse.getWebsite())
                .currentAccount(companyResponse.getCurrentAccount())
                .build();
    }

    @Override
    protected Response createResponse(@NonNull Company entity) {
        var builder = CompanyResponse.builder();
        super.initResponseBuilder(builder, entity);

        return builder
                .address(entity.getAddress())
                .edrpou(entity.getEdrpou())
                .website(entity.getWebsite())
                .currentAccount(entity.getCurrentAccount())
                .build();
    }

    @Override
    protected void deactivatedChildren(@NonNull Company entity) {
        deactivateChild(entity.getEdrpou(), edrpouService);
        deactivateChild(entity.getWebsite(), websiteService);
        deactivateChildrenCollection(entity.getPhones(), companyPhoneNumService);
        deactivateChildrenCollection(entity.getTariffs(), companyTariffService);
    }

    @Override
    protected void updateEntity(@NonNull Company entity, @NonNull Request request) {
        super.updateEntity(entity, request);
        var newValue = (CompanyRequest) request;

        if(!newValue.getAddress().isEmpty()){
            entity.setAddress(newValue.getAddress());
        }
        if(!newValue.getEdrpou().isEmpty()){
            entity.setEdrpou(newValue.getEdrpou());
        }
        if(!newValue.getWebsite().isEmpty()){
            entity.setWebsite(newValue.getWebsite());
        }
        if(!newValue.getCurrentAccount().isBlank()){
            entity.setCurrentAccount(newValue.getCurrentAccount());
        }
    }

    @Override
    protected void validationProcedureRequest(@NonNull Request request) throws InvalidInputDataException {
        super.validationProcedureRequest(request);
        var companyRequest = (CompanyRequest) request;

        validateCurrentAccount(companyRequest.getCurrentAccount());
    }

    private void validateCurrentAccount(@NonNull String currentAccount) throws InvalidInputDataException {
        if (isCurrentAccount(currentAccount)){
            return;
        }

        var message = String.format("The current account you provided: \"%s\" company has not been validated. It must contain exactly fourteen digits.", currentAccount);
        throwRuntimeException(message, InvalidInputDataException::new);
    }

    private boolean isCurrentAccount(@NonNull String currentAccount) {
        return currentAccount.isBlank() ||
                currentAccount
                .matches(CURRENT_ACCOUNT_TEMPLATE);
    }

    @Override
    protected Optional<Company> findEntity(@NonNull Request request) {
        var companyRequest = (CompanyRequest) request;
        return repository
                .findByCurrentAccount(
                        companyRequest.getCurrentAccount()
                );
    }
}
