package org.university.payment_for_utilities.services.implementations.bank;

import lombok.NonNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.university.payment_for_utilities.domains.bank.BankPhoneNum;
import org.university.payment_for_utilities.pojo.requests.bank.BankPhoneNumRequest;
import org.university.payment_for_utilities.pojo.requests.abstract_class.Request;
import org.university.payment_for_utilities.pojo.responses.bank.BankPhoneNumResponse;
import org.university.payment_for_utilities.pojo.responses.abstract_class.Response;
import org.university.payment_for_utilities.repositories.bank.BankPhoneNumRepository;
import org.university.payment_for_utilities.services.implementations.auxiliary_services.WorkingWithPhoneNumAbstract;
import org.university.payment_for_utilities.services.interfaces.bank.BankPhoneNumService;
import org.university.payment_for_utilities.services.interfaces.service_information_institutions.PhoneNumService;

import java.util.Optional;

@Service
public class BankPhoneNumServiceImpl extends WorkingWithPhoneNumAbstract<BankPhoneNum, BankPhoneNumRepository> implements BankPhoneNumService {
    private final PhoneNumService phoneNumService;

    @Autowired
    public BankPhoneNumServiceImpl(
            BankPhoneNumRepository repository,
            PhoneNumService phoneNumService
    ) {
        super(repository, "Bank phone nums");
        this.phoneNumService = phoneNumService;
    }

    @Override
    protected BankPhoneNum createEntity(Request request) {
        var bankPhoneNumRequest = (BankPhoneNumRequest) request;
        return BankPhoneNum
                .builder()
                .bank(bankPhoneNumRequest.getBank())
                .phoneNum(bankPhoneNumRequest.getPhoneNum())
                .build();
    }

    @Override
    protected BankPhoneNum createEntity(Response response) {
        var bankPhoneNumResponse = (BankPhoneNumResponse) response;
        var builder = BankPhoneNum.builder();
        initEntityBuilder(builder, response);

        return builder
                .bank(bankPhoneNumResponse.getBank())
                .phoneNum(bankPhoneNumResponse.getPhoneNum())
                .build();
    }

    @Override
    protected Response createResponse(@NonNull BankPhoneNum entity) {
        var builder = BankPhoneNumResponse.builder();
        initResponseBuilder(builder, entity);

        return builder
                .bank(entity.getBank())
                .phoneNum(entity.getPhoneNum())
                .build();
    }

    @Override
    protected void deactivatedChildren(@NonNull BankPhoneNum entity) {
        deactivateChild(entity.getPhoneNum(), phoneNumService);
    }

    @Override
    protected void updateEntity(@NonNull BankPhoneNum entity, @NonNull Request request) {
        var newValue = (BankPhoneNumRequest) request;

        if(!newValue.getBank().isEmpty()){
            entity.setBank(newValue.getBank());
        }
        if(!newValue.getPhoneNum().isEmpty()){
            entity.setPhoneNum(newValue.getPhoneNum());
        }
    }

    @Override
    protected Optional<BankPhoneNum> findEntity(@NonNull Request request) {
        var bankPhoneNumRequest = (BankPhoneNumRequest) request;
        return repository
                .findByBankAndPhoneNum(
                        bankPhoneNumRequest.getBank(),
                        bankPhoneNumRequest.getPhoneNum()
                );
    }
}
