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
import org.university.payment_for_utilities.pojo.requests.service_information_institutions.PhoneNumRequest;
import org.university.payment_for_utilities.pojo.responses.abstract_class.Response;
import org.university.payment_for_utilities.pojo.responses.service_information_institutions.PhoneNumResponse;
import org.university.payment_for_utilities.services.implementations.CrudServiceTest;
import org.university.payment_for_utilities.services.interfaces.service_information_institutions.PhoneNumService;

import java.util.stream.Stream;

@SpringBootTest
@Import(ServiceInfoEntitiesRequestTestContextConfiguration.class)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class PhoneNumServiceTest extends CrudServiceTest {
    @Autowired
    @Qualifier("companyPhoneNumRequest")
    private PhoneNumRequest companyPhoneNumRequest;
    @Autowired
    @Qualifier("bankPhoneNumRequest")
    private PhoneNumRequest bankPhoneNumRequest;

    @Autowired
    public PhoneNumServiceTest(PhoneNumService service) { super(service); }

    @BeforeEach
    @Override
    protected void initRequest() {
        firstRequest = companyPhoneNumRequest;
        secondRequest = bankPhoneNumRequest;
        emptyRequest = PhoneNumRequest
                .empty();
    }

    @Override
    protected Response updateExpectedResponse(@NonNull Response response) {
        return PhoneNumResponse
                .builder()
                .id(response.getId())
                .number("380632023541")
                .build();
    }

    @Override
    protected Request updateNewValue(@NonNull Response expectedResponse) {
        var response = (PhoneNumResponse) expectedResponse;
        return PhoneNumRequest
                .builder()
                .number(response.getNumber())
                .build();
    }

    @ParameterizedTest
    @MethodSource("testPhoneNums")
    @DisplayName("Check the exceptions when an invalid mobile phone number format is passed in the request.")
    void testPhoneThrowInvalidInputDataException(String num){
        var request = PhoneNumRequest
                .builder()
                .number(num)
                .build();

        addValueThrowInvalidInputData(request);
    }

    private static @NonNull Stream<Arguments> testPhoneNums(){
        return Stream.of(
                Arguments.of("380"),
                Arguments.of("380999999999999999"),
                Arguments.of("38044452f1365"),
                Arguments.of("38044452@1365"),
                Arguments.of("574445251365")
        );
    }
}
