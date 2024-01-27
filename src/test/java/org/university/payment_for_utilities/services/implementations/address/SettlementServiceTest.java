package org.university.payment_for_utilities.services.implementations.address;

import lombok.NonNull;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.annotation.DirtiesContext;
import org.university.payment_for_utilities.domains.address.SettlementName;
import org.university.payment_for_utilities.domains.address.TypeSettlement;
import org.university.payment_for_utilities.pojo.requests.address.SettlementRequest;
import org.university.payment_for_utilities.pojo.requests.abstract_class.Request;
import org.university.payment_for_utilities.pojo.responses.address.SettlementResponse;
import org.university.payment_for_utilities.pojo.responses.abstract_class.Response;
import org.university.payment_for_utilities.services.implementations.CrudServiceTest;
import org.university.payment_for_utilities.services.interfaces.address.SettlementService;

import java.util.stream.Stream;

@SpringBootTest
@Import(AddressEntitiesRequestTestContextConfiguration.class)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class SettlementServiceTest extends CrudServiceTest {
    @Autowired
    @Qualifier("settlementRivneRequest")
    private SettlementRequest settlementRivneRequest;
    @Autowired
    @Qualifier("settlementKyivRequest")
    private SettlementRequest settlementRequestKyiv;

    @Autowired
    public SettlementServiceTest(SettlementService service) {
        super(service);
    }

    @BeforeEach
    @Override
    protected void initRequest() {
        firstRequest = settlementRivneRequest;
        secondRequest = settlementRequestKyiv;
        emptyRequest = SettlementRequest
                .empty();
    }

    @Override
    protected Response updateExpectedResponse(@NonNull Response response) {
        return SettlementResponse
                .builder()
                .id(response.getId())
                .type(settlementRequestKyiv.getType())
                .zipCode("14523")
                .name(settlementRequestKyiv.getName())
                .build();
    }

    @Override
    protected Request updateNewValue(@NonNull Response expectedResponse) {
        var response = (SettlementResponse) expectedResponse;
        return SettlementRequest
                .builder()
                .type(TypeSettlement.empty())
                .zipCode(response.getZipCode())
                .name(SettlementName.empty())
                .build();
    }

    @ParameterizedTest
    @MethodSource("testPhoneZipCodes")
    @DisplayName("Check for exceptions when an invalid zip code format was passed in the request.")
    void testIndexThrowInvalidInputData(String zipCode){
        var request = (SettlementRequest) firstRequest;
        request.setZipCode(zipCode);
        addValueThrowInvalidInputData(request);
    }

    private static @NonNull Stream<Arguments> testPhoneZipCodes(){
        return Stream.of(
                Arguments.of("d5645"),
                Arguments.of("45$36"),
                Arguments.of("4")
        );
    }
}
