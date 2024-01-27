package org.university.payment_for_utilities.services.implementations.service_information_institutions;

import lombok.NonNull;
import org.jetbrains.annotations.Contract;
import org.springframework.stereotype.Service;
import org.university.payment_for_utilities.domains.service_information_institutions.PhoneNum;
import org.university.payment_for_utilities.exceptions.InvalidInputDataException;
import org.university.payment_for_utilities.pojo.requests.abstract_class.Request;
import org.university.payment_for_utilities.pojo.requests.service_information_institutions.PhoneNumRequest;
import org.university.payment_for_utilities.pojo.responses.abstract_class.Response;
import org.university.payment_for_utilities.pojo.responses.service_information_institutions.PhoneNumResponse;
import org.university.payment_for_utilities.repositories.service_information_institutions.PhoneNumRepository;
import org.university.payment_for_utilities.services.implementations.CrudServiceAbstract;
import org.university.payment_for_utilities.services.interfaces.service_information_institutions.PhoneNumService;

import java.util.Optional;

import static org.university.payment_for_utilities.services.implementations.tools.ExceptionTools.throwRuntimeException;

@Service
public class PhoneNumServiceImpl extends CrudServiceAbstract<PhoneNum, PhoneNumRepository> implements PhoneNumService {
    private static final String PHONE_NUM_TEMPLATE = "^380\\d{9}$";

    public PhoneNumServiceImpl(PhoneNumRepository repository) {
        super(repository, "Phone numbers");
    }

    @Override
    protected PhoneNum createEntity(Request request) {
        var phoneNumRequest = (PhoneNumRequest) request;
        return PhoneNum
                .builder()
                .number(phoneNumRequest.getNumber())
                .build();
    }

    @Override
    protected PhoneNum createEntity(Response response) {
        var phoneNumResponse = (PhoneNumResponse) response;
        var builder = PhoneNum.builder();
        initEntityBuilder(builder, phoneNumResponse);

        return builder
                .number(phoneNumResponse.getNumber())
                .build();
    }

    @Override
    protected Response createResponse(@NonNull PhoneNum entity) {
        var builder = PhoneNumResponse.builder();
        initResponseBuilder(builder, entity);

        return builder
                .number(entity.getNumber())
                .build();
    }

    @Override
    protected void updateEntity(@NonNull PhoneNum entity, @NonNull Request request) {
        var newValue = (PhoneNumRequest) request;

        if(!newValue.getNumber().isBlank()){
            entity.setNumber(newValue.getNumber());
        }
    }

    @Override
    protected void validationProcedureRequest(@NonNull Request request) throws InvalidInputDataException {
        var companyPhoneNumRequest = (PhoneNumRequest) request;
        validatePhoneNum(companyPhoneNumRequest.getNumber());
    }

    private void validatePhoneNum(String phoneNum) throws InvalidInputDataException {
        if (isValidPhoneNum(phoneNum)) {
            return;
        }

        var message = String.format("The mobile phone number you provided was not validated: \"%s\". The phone number must consist of twelve digits and start with \"380\".", phoneNum);
        throwRuntimeException(message, InvalidInputDataException::new);
    }

    @Contract(pure = true)
    private boolean isValidPhoneNum(@NonNull String phoneNum) {
        return phoneNum.isBlank() || phoneNum
                .matches(PHONE_NUM_TEMPLATE);
    }

    @Override
    protected Optional<PhoneNum> findEntity(@NonNull Request request) {
        var companyPhoneNumRequest = (PhoneNumRequest) request;
        return repository
                .findByNumber(
                        companyPhoneNumRequest.getNumber()
                );
    }
}
