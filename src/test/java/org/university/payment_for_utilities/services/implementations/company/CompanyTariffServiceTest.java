package org.university.payment_for_utilities.services.implementations.company;

import lombok.NonNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.annotation.DirtiesContext;
import org.university.payment_for_utilities.domains.company.Company;
import org.university.payment_for_utilities.domains.company.TypeOffer;
import org.university.payment_for_utilities.pojo.requests.abstract_class.Request;
import org.university.payment_for_utilities.pojo.requests.company.CompanyTariffRequest;
import org.university.payment_for_utilities.pojo.responses.abstract_class.Response;
import org.university.payment_for_utilities.pojo.responses.company.CompanyTariffResponse;
import org.university.payment_for_utilities.services.implementations.CrudServiceTest;
import org.university.payment_for_utilities.services.interfaces.company.CompanyTariffService;

import java.math.BigDecimal;

@SpringBootTest
@Import(CompanyEntitiesRequestTestContextConfiguration.class)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class CompanyTariffServiceTest extends CrudServiceTest {
    @Autowired
    @Qualifier("createRivneTariffRequest")
    private CompanyTariffRequest createRivneTariffRequest;
    @Autowired
    @Qualifier("createKyivTariffRequest")
    private CompanyTariffRequest createKyivTariffRequest;
    @Autowired
    @Qualifier("typeOfferUpdate")
    private TypeOffer typeOfferUpdate;

    @Autowired
    public CompanyTariffServiceTest(CompanyTariffService service) { super(service); }

    @BeforeEach
    @Override
    protected void initRequest() {
        firstRequest = createRivneTariffRequest;
        secondRequest = createKyivTariffRequest;
        emptyRequest = CompanyTariffRequest
                .empty();
    }

    @Override
    protected Response updateExpectedResponse(@NonNull Response response) {
        var fixedCost = createKyivTariffRequest.getFixedCost();
        return CompanyTariffResponse
                .builder()
                .id(response.getId())
                .company(createKyivTariffRequest.getCompany())
                .type(typeOfferUpdate)
                .name("Денний")
                .fixedCost(new BigDecimal(fixedCost))
                .build();
    }

    @Override
    protected Request updateNewValue(@NonNull Response expectedResponse) {
        var response = (CompanyTariffResponse) expectedResponse;
        return CompanyTariffRequest
                .builder()
                .company(Company.empty())
                .type(response.getType())
                .name(response.getName())
                .fixedCost("")
                .build();
    }

    @Test
    @DisplayName("Check for an exception when the user passed data in the wrong format to the \"name\" attribute.")
    void testValidateNameThrow(){
        var request = (CompanyTariffRequest) firstRequest;
        request.setName("fatal@_@data");
        addValueThrowInvalidInputData(request);
    }

    @Test
    @DisplayName("Check for an exception when the user passed data in the wrong format to the \"fixedCost\" attribute.")
    void testValidateFixedCostThrow(){
        var request = (CompanyTariffRequest) firstRequest;
        request.setFixedCost("13,5");
        addValueThrowInvalidInputData(request);
    }
}
