package org.university.payment_for_utilities.services.implementations.receipt;

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
import org.university.payment_for_utilities.domains.receipt.Receipt;
import org.university.payment_for_utilities.pojo.requests.abstract_class.Request;
import org.university.payment_for_utilities.pojo.requests.receipt.BlockMeterReadingRequest;
import org.university.payment_for_utilities.pojo.responses.abstract_class.Response;
import org.university.payment_for_utilities.pojo.responses.receipt.BlockMeterReadingResponse;
import org.university.payment_for_utilities.services.implementations.CrudServiceTest;
import org.university.payment_for_utilities.services.interfaces.receipt.BlockMeterReadingService;

import java.util.stream.Stream;

@SpringBootTest
@Import(ReceiptEntitiesRequestTestContextConfiguration.class)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class BlockMeterReadingServiceTest extends CrudServiceTest {
    @Autowired
    @Qualifier("rivneBlockMeter")
    private BlockMeterReadingRequest rivneBlockMeter;
    @Autowired
    @Qualifier("kyivBlockMeter")
    private BlockMeterReadingRequest kyivBlockMeter;

    @Autowired
    public BlockMeterReadingServiceTest(BlockMeterReadingService service) { super(service); }

    @BeforeEach
    @Override
    protected void initRequest() {
        firstRequest = rivneBlockMeter;
        secondRequest = kyivBlockMeter;
        emptyRequest = BlockMeterReadingRequest
                .empty();
    }

    @Override
    protected Response updateExpectedResponse(@NonNull Response response) {
        return BlockMeterReadingResponse
                .builder()
                .id(response.getId())
                .receipt(kyivBlockMeter.getReceipt())
                .prevValueCounter(101f)
                .currentValueCounter(125.3f)
                .build();
    }

    @Override
    protected Request updateNewValue(@NonNull Response expectedResponse) {
        var response = (BlockMeterReadingResponse) expectedResponse;
        return BlockMeterReadingRequest
                .builder()
                .receipt(Receipt.empty())
                .prevValueCounter(response.getPrevValueCounter())
                .currentValueCounter(response.getCurrentValueCounter())
                .build();
    }

    @ParameterizedTest
    @MethodSource("testPrevValueCounters")
    @DisplayName("Check for exceptions when the current counter value is lower than the previous one.")
    void testValidatePrevValueCounterThrow(Float previousValue, Float currentValue) {
        var request = (BlockMeterReadingRequest) firstRequest;
        request.setPrevValueCounter(previousValue);
        request.setCurrentValueCounter(currentValue);
        addValueThrowInvalidInputData(request);
    }

    private static @NonNull Stream<Arguments> testPrevValueCounters() {
        return Stream.of(
                Arguments.of(12f, 10f),
                Arguments.of(10f, 10f)
        );
    }
}
