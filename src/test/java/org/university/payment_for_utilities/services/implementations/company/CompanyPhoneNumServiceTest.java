package org.university.payment_for_utilities.services.implementations.company;

import lombok.NonNull;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.annotation.DirtiesContext;
import org.university.payment_for_utilities.domains.company.Company;
import org.university.payment_for_utilities.domains.service_information_institutions.PhoneNum;
import org.university.payment_for_utilities.pojo.requests.company.CompanyPhoneNumRequest;
import org.university.payment_for_utilities.pojo.requests.abstract_class.Request;
import org.university.payment_for_utilities.pojo.responses.company.CompanyPhoneNumResponse;
import org.university.payment_for_utilities.pojo.responses.abstract_class.Response;
import org.university.payment_for_utilities.services.implementations.CrudServiceTest;
import org.university.payment_for_utilities.services.interfaces.company.CompanyPhoneNumService;

@SpringBootTest
@Import(CompanyEntitiesRequestTestContextConfiguration.class)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class CompanyPhoneNumServiceTest extends CrudServiceTest {
    @Autowired
    @Qualifier("companyRivneOblenergoPhoneNumRequest")
    private CompanyPhoneNumRequest companyPhoneNumRequest;
    @Autowired
    @Qualifier("companyKyivOblenergoPhoneNumRequest")
    private CompanyPhoneNumRequest companyKyivOblenergoPhoneNumRequest;
    @Autowired
    @Qualifier("updateBankPhoneNum")
    private PhoneNum updateBankPhoneNum;

    @Autowired
    public CompanyPhoneNumServiceTest(CompanyPhoneNumService service) { super(service); }

    @BeforeEach
    @Override
    protected void initRequest() {
        firstRequest = companyPhoneNumRequest;
        secondRequest = companyKyivOblenergoPhoneNumRequest;
        emptyRequest = CompanyPhoneNumRequest
                .empty();
    }

    @Override
    protected Response updateExpectedResponse(@NonNull Response response) {
        return CompanyPhoneNumResponse
                .builder()
                .id(response.getId())
                .company(companyKyivOblenergoPhoneNumRequest.getCompany())
                .phoneNum(updateBankPhoneNum)
                .build();
    }

    @Override
    protected Request updateNewValue(@NonNull Response expectedResponse) {
        var response = (CompanyPhoneNumResponse) expectedResponse;
        return CompanyPhoneNumRequest
                .builder()
                .company(Company.empty())
                .phoneNum(response.getPhoneNum())
                .build();
    }
}
