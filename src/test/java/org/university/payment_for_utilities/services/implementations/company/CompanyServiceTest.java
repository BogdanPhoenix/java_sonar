package org.university.payment_for_utilities.services.implementations.company;

import lombok.NonNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.annotation.DirtiesContext;
import org.university.payment_for_utilities.domains.address.AddressResidence;
import org.university.payment_for_utilities.domains.service_information_institutions.Edrpou;
import org.university.payment_for_utilities.domains.service_information_institutions.Website;
import org.university.payment_for_utilities.pojo.requests.company.CompanyRequest;
import org.university.payment_for_utilities.pojo.requests.abstract_class.Request;
import org.university.payment_for_utilities.pojo.responses.company.CompanyResponse;
import org.university.payment_for_utilities.pojo.responses.abstract_class.Response;
import org.university.payment_for_utilities.services.implementations.CrudServiceTest;
import org.university.payment_for_utilities.services.interfaces.company.CompanyService;

import java.util.stream.Stream;

@SpringBootTest
@Import(CompanyEntitiesRequestTestContextConfiguration.class)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class CompanyServiceTest extends CrudServiceTest {
    @Autowired
    @Qualifier("companyRivneOblenergoRequest")
    private CompanyRequest companyRivneOblenergoRequest;
    @Autowired
    @Qualifier("companyKyivOblenergoRequest")
    private CompanyRequest companyKyivOblenergoRequest;

    @Autowired
    public CompanyServiceTest(CompanyService service) { super(service); }

    @BeforeEach
    @Override
    protected void initRequest(){
        firstRequest = companyRivneOblenergoRequest;
        secondRequest = companyKyivOblenergoRequest;
        emptyRequest = CompanyRequest
                .empty();
    }

    @Override
    protected Response updateExpectedResponse(@NonNull Response response) {
        return CompanyResponse
                .builder()
                .id(response.getId())
                .address(companyKyivOblenergoRequest.getAddress())
                .edrpou(companyKyivOblenergoRequest.getEdrpou())
                .website(companyKyivOblenergoRequest.getWebsite())
                .uaName("Київ-обленерго")
                .enName("Kyivoblenergo")
                .currentAccount("72341000245521")
                .build();
    }

    @Override
    protected Request updateNewValue(@NonNull Response expectedResponse) {
        var response = (CompanyResponse) expectedResponse;
        return CompanyRequest
                .builder()
                .address(AddressResidence.empty())
                .edrpou(Edrpou.empty())
                .website(Website.empty())
                .uaName(response.getUaName())
                .enName(response.getEnName())
                .currentAccount(response.getCurrentAccount())
                .build();
    }

    @ParameterizedTest
    @MethodSource("testCurrentAccounts")
    @DisplayName("Check the exceptions if the request has an incorrect current account format.")
    void testCurrentAccountThrowInvalidInputDataException(String numAccount){
        var request = (CompanyRequest) firstRequest;
        request.setCurrentAccount(numAccount);

        addValueThrowInvalidInputData(request);
    }

    private static @NonNull Stream<Arguments> testCurrentAccounts(){
        return Stream.of(
                Arguments.of("4236895213g575"),
                Arguments.of("752139$7512452"),
                Arguments.of("452136"),
                Arguments.of("145236985123654786")
        );
    }
}
