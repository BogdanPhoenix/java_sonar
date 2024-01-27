package org.university.payment_for_utilities.services.implementations.service_information_institutions;

import lombok.NonNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.annotation.DirtiesContext;
import org.university.payment_for_utilities.pojo.requests.abstract_class.Request;
import org.university.payment_for_utilities.pojo.requests.service_information_institutions.UnitMeasurementRequest;
import org.university.payment_for_utilities.pojo.responses.abstract_class.Response;
import org.university.payment_for_utilities.pojo.responses.service_information_institutions.UnitMeasurementResponse;
import org.university.payment_for_utilities.services.implementations.TransliterationServiceTest;
import org.university.payment_for_utilities.services.interfaces.service_information_institutions.UnitMeasurementService;

@SpringBootTest
@Import(ServiceInfoEntitiesRequestTestContextConfiguration.class)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
public class UnitMeasurementServiceTest extends TransliterationServiceTest {
    @Autowired
    @Qualifier("unitKilowattRequest")
    private UnitMeasurementRequest unitKilowattRequest;
    @Autowired
    @Qualifier("unitCubicMeterRequest")
    private UnitMeasurementRequest unitCubicMeterRequest;

    @Autowired
    public UnitMeasurementServiceTest(UnitMeasurementService service) { super(service); }

    @BeforeEach
    @Override
    protected void initRequest() {
        firstRequest = unitKilowattRequest;
        secondRequest = unitCubicMeterRequest;
        emptyRequest = UnitMeasurementRequest
                .empty();
    }

    @Override
    protected Response updateExpectedResponse(@NonNull Response response) {
        return UnitMeasurementResponse
                .builder()
                .id(response.getId())
                .uaName("куб. м.")
                .enName("new data")
                .build();
    }

    @Override
    protected Request updateNewValue(@NonNull Response expectedResponse) {
        var response = (UnitMeasurementResponse) expectedResponse;
        return UnitMeasurementRequest
                .builder()
                .uaName("")
                .enName(response.getEnName())
                .build();
    }

    @Test
    @DisplayName("Checking for an exception when data in an incorrect format was passed in a request.")
    @Override
    protected void testAddValueThrowInvalidInputData() {
        var withNum = UnitMeasurementRequest
                .builder()
                .uaName("кілова4т")
                .enName("kilo5watt")
                .build();

        var withSpecialCharacter = UnitMeasurementRequest
                .builder()
                .uaName("кілова$т")
                .enName("kilow@att")
                .build();

        testAddValueThrowInvalidInputData(withNum, withSpecialCharacter);
    }

    @Test
    @DisplayName("Check for exceptions when data was transferred in an incorrect format in an update request.")
    @Override
    protected void testUpdateValueThrowInvalidInputData() {
        var incorrectRequest = UnitMeasurementRequest
                .builder()
                .uaName("кілова4т")
                .enName("kilowatt")
                .build();

        testUpdateValueThrowInvalidInputData(incorrectRequest);
    }
}
