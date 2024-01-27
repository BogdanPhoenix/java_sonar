package org.university.payment_for_utilities.services.implementations.bank;

import lombok.NonNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.university.payment_for_utilities.domains.bank.Bank;
import org.university.payment_for_utilities.exceptions.InvalidInputDataException;
import org.university.payment_for_utilities.pojo.requests.bank.BankRequest;
import org.university.payment_for_utilities.pojo.requests.abstract_class.Request;
import org.university.payment_for_utilities.pojo.responses.bank.BankResponse;
import org.university.payment_for_utilities.pojo.responses.abstract_class.Response;
import org.university.payment_for_utilities.repositories.bank.BankRepository;
import org.university.payment_for_utilities.services.implementations.auxiliary_services.TransliterationService;
import org.university.payment_for_utilities.services.interfaces.bank.BankPhoneNumService;
import org.university.payment_for_utilities.services.interfaces.bank.BankService;
import org.university.payment_for_utilities.services.interfaces.receipt.ReceiptService;
import org.university.payment_for_utilities.services.interfaces.service_information_institutions.EdrpouService;
import org.university.payment_for_utilities.services.interfaces.service_information_institutions.WebsiteService;

import java.util.Optional;

import static org.university.payment_for_utilities.services.implementations.tools.ExceptionTools.throwRuntimeException;

@Service
public class BankServiceImpl extends TransliterationService<Bank, BankRepository> implements BankService {
    private static final String MFO_TEMPLATE = "^\\d{6}$";
    private final EdrpouService edrpouService;
    private final WebsiteService websiteService;
    private final BankPhoneNumService bankPhoneNumService;
    private final ReceiptService receiptService;

    @Autowired
    public BankServiceImpl(
            BankRepository repository,
            EdrpouService edrpouService,
            WebsiteService websiteService,
            BankPhoneNumService bankPhoneNumService,
            ReceiptService receiptService
    ) {
        super(repository, "Banks");
        this.edrpouService = edrpouService;
        this.websiteService = websiteService;
        this.bankPhoneNumService = bankPhoneNumService;
        this.receiptService = receiptService;
    }

    @Override
    protected Bank createEntity(Request request) {
        var builder = Bank.builder();
        super.initTransliterationPropertyBuilder(builder, request);
        var bankRequest = (BankRequest) request;

        return builder
                .website(bankRequest.getWebsite())
                .edrpou(bankRequest.getEdrpou())
                .mfo(bankRequest.getMfo())
                .build();
    }

    @Override
    protected Bank createEntity(Response response) {
        var bankResponse = (BankResponse) response;
        var builder = Bank.builder();
        super.initTransliterationPropertyBuilder(builder, response);

        return builder
                .website(bankResponse.getWebsite())
                .edrpou(bankResponse.getEdrpou())
                .mfo(bankResponse.getMfo())
                .build();
    }

    @Override
    protected Response createResponse(@NonNull Bank entity) {
        var builder = BankResponse.builder();
        super.initResponseBuilder(builder, entity);

        return builder
                .website(entity.getWebsite())
                .edrpou(entity.getEdrpou())
                .mfo(entity.getMfo())
                .build();
    }

    @Override
    protected void deactivatedChildren(@NonNull Bank entity) {
        edrpouService.removeValue(entity.getEdrpou().getId());
        websiteService.removeValue(entity.getWebsite().getId());
        deactivateChildrenCollection(entity.getPhones(), bankPhoneNumService);
        deactivateChildrenCollection(entity.getReceipts(), receiptService);
    }

    @Override
    protected void updateEntity(@NonNull Bank entity, @NonNull Request request) {
        super.updateEntity(entity, request);
        var newValue = (BankRequest) request;

        if(!newValue.getWebsite().isEmpty()){
            entity.setWebsite(newValue.getWebsite());
        }
        if(!newValue.getEdrpou().isEmpty()){
            entity.setEdrpou(newValue.getEdrpou());
        }
        if(!newValue.getMfo().isBlank()){
            entity.setMfo(newValue.getMfo());
        }
    }

    @Override
    protected void validationProcedureRequest(@NonNull Request request) throws InvalidInputDataException {
        super.validationProcedureRequest(request);

        var bankRequest = (BankRequest) request;
        validateMfo(bankRequest.getMfo());
    }

    private void validateMfo(@NonNull String mfo) throws InvalidInputDataException {
        if (isMfo(mfo)){
            return;
        }

        var message = String.format("The MFO you provided: \"%s\" of the bank has not been validated. It should contain only six digits.", mfo);
        throwRuntimeException(message, InvalidInputDataException::new);
    }

    private boolean isMfo(@NonNull String mfo){
        return mfo.isEmpty() ||
                mfo.matches(MFO_TEMPLATE);
    }

    @Override
    protected Optional<Bank> findEntity(@NonNull Request request) {
        var bankRequest = (BankRequest) request;
        return repository
                .findByMfo(
                        bankRequest.getMfo()
                );
    }
}
