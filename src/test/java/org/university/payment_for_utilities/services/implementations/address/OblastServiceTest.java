package org.university.payment_for_utilities.services.implementations.address;

import lombok.NonNull;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.annotation.DirtiesContext;
import org.university.payment_for_utilities.pojo.requests.address.OblastRequest;
import org.university.payment_for_utilities.pojo.requests.abstract_class.Request;
import org.university.payment_for_utilities.pojo.responses.address.OblastResponse;
import org.university.payment_for_utilities.pojo.responses.abstract_class.Response;
import org.university.payment_for_utilities.services.implementations.TransliterationServiceTest;
import org.university.payment_for_utilities.services.interfaces.address.OblastService;

@SpringBootTest
@Import(AddressEntitiesRequestTestContextConfiguration.class)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class OblastServiceTest extends TransliterationServiceTest {
    @Autowired
    @Qualifier("oblastRivneRequest")
    private OblastRequest rivneRequest;
    @Autowired
    @Qualifier("oblastKyivRequest")
    private OblastRequest kyivRequest;

    @Autowired
    public OblastServiceTest(OblastService service) {
        super(service);
    }

    @BeforeEach
    @Override
    protected void initRequest(){
        firstRequest = rivneRequest;
        secondRequest = kyivRequest;
        emptyRequest = OblastRequest
                .empty();
    }

    @Override
    protected Response updateExpectedResponse(@NonNull Response response) {
        return OblastResponse
                .builder()
                .id(response.getId())
                .uaName("Київська")
                .enName("other")
                .build();
    }

    @Override
    protected Request updateNewValue(@NonNull Response expectedResponse) {
        var response = (OblastResponse) expectedResponse;
        return OblastRequest
                .builder()
                .uaName("")
                .enName(response.getEnName())
                .build();
    }

    @Test
    @DisplayName("Checking for an exception when data in an incorrect format was passed in a request.")
    @Override
    protected void testAddValueThrowInvalidInputData() {
        var withNum = OblastRequest
                .builder()
                .uaName("Рівн5енська")
                .enName("Rivnenska")
                .build();
        var withSpecialCharacter = OblastRequest
                .builder()
                .uaName("Рівн@енська")
                .enName("Rivnenska")
                .build();

        testAddValueThrowInvalidInputData(withNum, withSpecialCharacter);
    }

    @Test
    @DisplayName("Check for exceptions when data was transferred in an incorrect format in an update request.")
    @Override
    protected void testUpdateValueThrowInvalidInputData(){
        var incorrectRequest = OblastRequest
                .builder()
                .uaName("Рівне5нська")
                .enName("Rivne")
                .build();

        testUpdateValueThrowInvalidInputData(incorrectRequest);
    }
}
