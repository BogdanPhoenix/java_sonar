package org.university.payment_for_utilities.services.implementations.address;

import lombok.NonNull;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.annotation.DirtiesContext;
import org.university.payment_for_utilities.pojo.requests.address.DistrictRequest;
import org.university.payment_for_utilities.pojo.requests.abstract_class.Request;
import org.university.payment_for_utilities.pojo.responses.address.DistrictResponse;
import org.university.payment_for_utilities.pojo.responses.abstract_class.Response;
import org.university.payment_for_utilities.services.implementations.TransliterationServiceTest;
import org.university.payment_for_utilities.services.interfaces.address.DistrictService;

@SpringBootTest
@Import(AddressEntitiesRequestTestContextConfiguration.class)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class DistrictServiceTest extends TransliterationServiceTest {
    @Autowired
    @Qualifier("districtRivneRequest")
    private DistrictRequest rivneRequest;
    @Autowired
    @Qualifier("districtBelotserkivskyiRequest")
    private DistrictRequest belotserkivskyiRequest;

    @Autowired
    public DistrictServiceTest(DistrictService service) {
        super(service);
    }

    @BeforeEach
    @Override
    protected void initRequest(){
        firstRequest = rivneRequest;
        secondRequest = belotserkivskyiRequest;
        emptyRequest = DistrictRequest
                .empty();
    }

    @Override
    protected Response updateExpectedResponse(@NonNull Response response) {
        return DistrictResponse
                .builder()
                .id(response.getId())
                .uaName("Білоцерківський")
                .enName("other")
                .build();
    }

    @Override
    protected Request updateNewValue(@NonNull Response expectedResponse) {
        var response = (DistrictResponse) expectedResponse;
        return DistrictRequest
                .builder()
                .uaName("")
                .enName(response.getEnName())
                .build();
    }

    @Test
    @DisplayName("Checking for an exception when data in an incorrect format was passed in a request.")
    @Override
    protected void testAddValueThrowInvalidInputData() {
        var withNum = DistrictRequest
                .builder()
                .uaName("Рівн5енський")
                .enName("Rivne")
                .build();
        var withSpecialCharacter = DistrictRequest
                .builder()
                .uaName("Рівн@енський")
                .enName("Rivne")
                .build();

        testAddValueThrowInvalidInputData(withNum, withSpecialCharacter);
    }

    @Test
    @DisplayName("Check for exceptions when data was transferred in an incorrect format in an update request.")
    @Override
    protected void testUpdateValueThrowInvalidInputData(){
        var incorrectRequest = DistrictRequest
                .builder()
                .uaName("Рівне5нський")
                .enName("Rivne")
                .build();

        testUpdateValueThrowInvalidInputData(incorrectRequest);
    }
}
