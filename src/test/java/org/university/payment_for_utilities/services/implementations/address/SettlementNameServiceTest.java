package org.university.payment_for_utilities.services.implementations.address;

import lombok.NonNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.annotation.DirtiesContext;
import org.university.payment_for_utilities.pojo.requests.address.SettlementNameRequest;
import org.university.payment_for_utilities.pojo.requests.abstract_class.Request;
import org.university.payment_for_utilities.pojo.responses.address.SettlementNameResponse;
import org.university.payment_for_utilities.pojo.responses.abstract_class.Response;
import org.university.payment_for_utilities.services.implementations.TransliterationServiceTest;
import org.university.payment_for_utilities.services.interfaces.address.SettlementNameService;

@SpringBootTest
@Import(AddressEntitiesRequestTestContextConfiguration.class)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class SettlementNameServiceTest extends TransliterationServiceTest {
    @Autowired
    @Qualifier("nameRivneRequest")
    private SettlementNameRequest rivneRequest;
    @Autowired
    @Qualifier("nameKyivRequest")
    private SettlementNameRequest kyivRequest;

    @Autowired
    public SettlementNameServiceTest(SettlementNameService service){
        super(service);
    }

    @BeforeEach
    @Override
    protected void initRequest() {
        firstRequest = rivneRequest;
        secondRequest = kyivRequest;
        emptyRequest = SettlementNameRequest
                .empty();
    }

    @Override
    protected Response updateExpectedResponse(@NonNull Response response) {
        return SettlementNameResponse
                .builder()
                .id(response.getId())
                .uaName("Київ")
                .enName("other")
                .build();
    }

    @Override
    protected Request updateNewValue(@NonNull Response expectedResponse) {
        var response = (SettlementNameResponse) expectedResponse;
        return SettlementNameRequest
                .builder()
                .uaName("")
                .enName(response.getEnName())
                .build();
    }

    @Test
    @DisplayName("Checking for an exception when data in an incorrect format was passed in a request.")
    @Override
    protected void testAddValueThrowInvalidInputData(){
        var withNum = SettlementNameRequest
                .builder()
                .uaName("Грин9івка")
                .enName("Hrynivka")
                .build();

        var withSpecialCharacter = SettlementNameRequest
                .builder()
                .uaName("Гринівка")
                .enName("Hry^nivka")
                .build();

        testAddValueThrowInvalidInputData(withNum, withSpecialCharacter);
    }

    @Test
    @DisplayName("Check for exceptions when data was transferred in an incorrect format in an update request.")
    @Override
    protected void testUpdateValueThrowInvalidInputData(){
        var incorrectRequest = SettlementNameRequest
                .builder()
                .uaName("Грин9івка")
                .enName("Hrynivka")
                .build();

        testUpdateValueThrowInvalidInputData(incorrectRequest);
    }
}
