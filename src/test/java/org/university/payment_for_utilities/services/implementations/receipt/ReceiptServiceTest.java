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
import org.university.payment_for_utilities.domains.user.ContractEntity;
import org.university.payment_for_utilities.pojo.requests.abstract_class.Request;
import org.university.payment_for_utilities.pojo.requests.receipt.ReceiptRequest;
import org.university.payment_for_utilities.pojo.responses.abstract_class.Response;
import org.university.payment_for_utilities.pojo.responses.receipt.ReceiptResponse;
import org.university.payment_for_utilities.services.implementations.CrudServiceTest;
import org.university.payment_for_utilities.services.interfaces.receipt.ReceiptService;

import java.time.LocalDate;
import java.time.Month;
import java.util.stream.Stream;

@SpringBootTest
@Import(ReceiptEntitiesRequestTestContextConfiguration.class)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class ReceiptServiceTest extends CrudServiceTest {
    @Autowired
    @Qualifier("rivneReceiptRequest")
    private ReceiptRequest rivneReceiptRequest;
    @Autowired
    @Qualifier("kyivReceiptRequest")
    private ReceiptRequest kyivReceiptRequest;

    @Autowired
    public ReceiptServiceTest(ReceiptService service) { super(service); }

    @BeforeEach
    @Override
    protected void initRequest() {
        firstRequest = rivneReceiptRequest;
        secondRequest = kyivReceiptRequest;
        emptyRequest = ReceiptRequest
                .empty();
    }

    @Override
    protected Response updateExpectedResponse(@NonNull Response response) {
        return ReceiptResponse
                .builder()
                .id(response.getId())
                .contractEntity(kyivReceiptRequest.getContractEntity())
                .bank(rivneReceiptRequest.getBank())
                .billMonth(LocalDate.of(2023, Month.DECEMBER, 5))
                .build();
    }

    @Override
    protected Request updateNewValue(@NonNull Response expectedResponse) {
        var response = (ReceiptResponse) expectedResponse;
        return ReceiptRequest
                .builder()
                .contractEntity(ContractEntity.empty())
                .bank(response.getBank())
                .billMonth(response.getBillMonth())
                .build();
    }

    @ParameterizedTest
    @MethodSource("testBillMonths")
    @DisplayName("Check for exceptions when the specified month and year do not pass validation.")
    void testValidateBillMonths(LocalDate month) {
        var request = (ReceiptRequest) firstRequest;
        request.setBillMonth(month);
        addValueThrowInvalidInputData(request);
    }

    private static @NonNull Stream<Arguments> testBillMonths() {
        return Stream.of(
                Arguments.of(LocalDate.of(2022, Month.APRIL, 1)),
                Arguments.of(LocalDate.of(2024, Month.JULY, 1))
        );
    }
}
