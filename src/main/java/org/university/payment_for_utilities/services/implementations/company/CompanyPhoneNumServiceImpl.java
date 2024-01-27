package org.university.payment_for_utilities.services.implementations.company;

import lombok.NonNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.university.payment_for_utilities.domains.company.CompanyPhoneNum;
import org.university.payment_for_utilities.pojo.requests.company.CompanyPhoneNumRequest;
import org.university.payment_for_utilities.pojo.requests.abstract_class.Request;
import org.university.payment_for_utilities.pojo.responses.company.CompanyPhoneNumResponse;
import org.university.payment_for_utilities.pojo.responses.abstract_class.Response;
import org.university.payment_for_utilities.repositories.company.CompanyPhoneNumRepository;
import org.university.payment_for_utilities.services.implementations.auxiliary_services.WorkingWithPhoneNumAbstract;
import org.university.payment_for_utilities.services.interfaces.company.CompanyPhoneNumService;
import org.university.payment_for_utilities.services.interfaces.service_information_institutions.PhoneNumService;

import java.util.Optional;

@Service
public class CompanyPhoneNumServiceImpl extends WorkingWithPhoneNumAbstract<CompanyPhoneNum, CompanyPhoneNumRepository> implements CompanyPhoneNumService {
    private final PhoneNumService phoneNumService;

    @Autowired
    public CompanyPhoneNumServiceImpl(
            CompanyPhoneNumRepository repository,
            PhoneNumService phoneNumService
    ) {
        super(repository, "Company phone nums");
        this.phoneNumService = phoneNumService;
    }

    @Override
    protected CompanyPhoneNum createEntity(Request request) {
        var companyPhoneNumRequest = (CompanyPhoneNumRequest) request;
        return CompanyPhoneNum
                .builder()
                .company(companyPhoneNumRequest.getCompany())
                .phoneNum(companyPhoneNumRequest.getPhoneNum())
                .build();
    }

    @Override
    protected CompanyPhoneNum createEntity(Response response) {
        var companyPhoneNumResponse = (CompanyPhoneNumResponse) response;
        var builder = CompanyPhoneNum.builder();
        initEntityBuilder(builder, response);

        return builder
                .company(companyPhoneNumResponse.getCompany())
                .phoneNum(companyPhoneNumResponse.getPhoneNum())
                .build();
    }

    @Override
    protected Response createResponse(@NonNull CompanyPhoneNum entity) {
        var builder = CompanyPhoneNumResponse.builder();
        initResponseBuilder(builder, entity);

        return builder
                .company(entity.getCompany())
                .phoneNum(entity.getPhoneNum())
                .build();
    }

    @Override
    protected void deactivatedChildren(@NonNull CompanyPhoneNum entity) {
        deactivateChild(entity.getPhoneNum(), phoneNumService);
    }

    @Override
    protected void updateEntity(@NonNull CompanyPhoneNum entity, @NonNull Request request) {
        var newValue = (CompanyPhoneNumRequest) request;

        if(!newValue.getCompany().isEmpty()){
            entity.setCompany(newValue.getCompany());
        }
        if (!newValue.getPhoneNum().isEmpty()){
            entity.setPhoneNum(newValue.getPhoneNum());
        }
    }

    @Override
    protected Optional<CompanyPhoneNum> findEntity(@NonNull Request request) {
        var companyPhoneNumRequest = (CompanyPhoneNumRequest) request;
        return repository
                .findByCompanyAndPhoneNum(
                        companyPhoneNumRequest.getCompany(),
                        companyPhoneNumRequest.getPhoneNum()
                );
    }
}
