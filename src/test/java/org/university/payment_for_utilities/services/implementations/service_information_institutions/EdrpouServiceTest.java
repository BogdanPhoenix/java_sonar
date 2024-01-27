package org.university.payment_for_utilities.services.implementations.service_information_institutions;

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
import org.university.payment_for_utilities.pojo.requests.abstract_class.Request;
import org.university.payment_for_utilities.pojo.requests.service_information_institutions.EdrpouRequest;
import org.university.payment_for_utilities.pojo.responses.abstract_class.Response;
import org.university.payment_for_utilities.pojo.responses.service_information_institutions.EdrpouResponse;
import org.university.payment_for_utilities.services.implementations.CrudServiceTest;
import org.university.payment_for_utilities.services.interfaces.service_information_institutions.EdrpouService;

import java.util.stream.Stream;

@SpringBootTest
@Import(ServiceInfoEntitiesRequestTestContextConfiguration.class)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class EdrpouServiceTest extends CrudServiceTest {
    @Autowired
    @Qualifier("privateBankEdrpouRequest")
    private EdrpouRequest privateBankEdrpouRequest;
    @Autowired
    @Qualifier("raiffeisenBankEdrpouRequest")
    private EdrpouRequest raiffeisenBankEdrpouRequest;

    @Autowired
    public EdrpouServiceTest(EdrpouService service) { super(service); }

    @BeforeEach
    @Override
    protected void initRequest(){
        firstRequest = privateBankEdrpouRequest;
        secondRequest = raiffeisenBankEdrpouRequest;
        emptyRequest = EdrpouRequest
                .empty();
    }

    @Override
    protected Response updateExpectedResponse(@NonNull Response response) {
        return EdrpouResponse
                .builder()
                .id(response.getId())
                .value("75231456")
                .build();
    }

    @Override
    protected Request updateNewValue(@NonNull Response expectedResponse) {
        var response = (EdrpouResponse) expectedResponse;
        return EdrpouRequest
                .builder()
                .value(response.getValue())
                .build();
    }


    @ParameterizedTest
    @MethodSource("testPhoneEdrpous")
    @DisplayName("Check for exceptions when the request has an invalid EDRPOU format.")
    void testWedEdrpouThrowInvalidInputDataException(String edrpou){
        var request = EdrpouRequest
                .builder()
                .value(edrpou)
                .build();

        addValueThrowInvalidInputData(request);
    }

    private static @NonNull Stream<Arguments> testPhoneEdrpous(){
        return Stream.of(
                Arguments.of("14360b570"),
                Arguments.of("143605%70"),
                Arguments.of("1436"),
                Arguments.of("1436750570")
        );
    }
}
