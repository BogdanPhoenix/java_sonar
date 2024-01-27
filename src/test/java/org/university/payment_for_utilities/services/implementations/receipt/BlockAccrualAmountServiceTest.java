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
import org.university.payment_for_utilities.pojo.requests.receipt.BlockAccrualAmountRequest;
import org.university.payment_for_utilities.pojo.responses.abstract_class.Response;
import org.university.payment_for_utilities.pojo.responses.receipt.BlockAccrualAmountResponse;
import org.university.payment_for_utilities.services.implementations.CrudServiceTest;
import org.university.payment_for_utilities.services.interfaces.receipt.BlockAccrualAmountService;

import java.math.BigDecimal;
import java.util.stream.Stream;

@SpringBootTest
@Import(ReceiptEntitiesRequestTestContextConfiguration.class)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class BlockAccrualAmountServiceTest extends CrudServiceTest {
    @Autowired
    @Qualifier("rivneAccrualAmountRequest")
    private BlockAccrualAmountRequest rivneAccrualAmountRequest;
    @Autowired
    @Qualifier("kyivAccrualAmountRequest")
    private BlockAccrualAmountRequest kyivAccrualAmountRequest;

    @Autowired
    public BlockAccrualAmountServiceTest(BlockAccrualAmountService service) { super(service); }

    @BeforeEach
    @Override
    protected void initRequest() {
        firstRequest = rivneAccrualAmountRequest;
        secondRequest = kyivAccrualAmountRequest;
        emptyRequest = BlockAccrualAmountRequest
                .empty();
    }

    @Override
    protected Response updateExpectedResponse(@NonNull Response response) {
        var lastCredited = new BigDecimal(kyivAccrualAmountRequest.getLastCreditedPayment());
        var amountDue = new BigDecimal(kyivAccrualAmountRequest.getAmountDue());

        return BlockAccrualAmountResponse
                .builder()
                .id(response.getId())
                .receipt(kyivAccrualAmountRequest.getReceipt())
                .debtBeginMonth(new BigDecimal("455.02"))
                .debtEndMonth(new BigDecimal("202.20"))
                .fine(new BigDecimal("510.00"))
                .lastCreditedPayment(lastCredited)
                .amountDue(amountDue)
                .build();
    }

    @Override
    protected Request updateNewValue(@NonNull Response expectedResponse) {
        var response = (BlockAccrualAmountResponse) expectedResponse;
        return BlockAccrualAmountRequest
                .builder()
                .receipt(Receipt.empty())
                .debtBeginMonth(response.getDebtBeginMonth().toString())
                .debtEndMonth(response.getDebtEndMonth().toString())
                .fine(response.getFine().toString())
                .lastCreditedPayment("")
                .amountDue("")
                .build();
    }

    @ParameterizedTest
    @MethodSource("testFinanceData")
    @DisplayName("Check exceptions when the debt entered at the beginning of the month is incorrect.")
    void testValidateDebtBeginMonthThrowInvalidInputDataException(String debtBegin) {
        var request = (BlockAccrualAmountRequest) firstRequest;
        request.setDebtBeginMonth(debtBegin);
        addValueThrowInvalidInputData(request);
    }

    @ParameterizedTest
    @MethodSource("testFinanceData")
    @DisplayName("Check exceptions when the entered debt at the end of the month is incorrect.")
    void testValidateDebtEndMonthThrowInvalidInputDataException(String debtEnd) {
        var request = (BlockAccrualAmountRequest) firstRequest;
        request.setDebtEndMonth(debtEnd);
        addValueThrowInvalidInputData(request);
    }

    @ParameterizedTest
    @MethodSource("testFinanceData")
    @DisplayName("Check exceptions when the entered penalty is incorrect.")
    void testValidateFineThrowInvalidInputDataException(String fine) {
        var request = (BlockAccrualAmountRequest) firstRequest;
        request.setFine(fine);
        addValueThrowInvalidInputData(request);
    }

    @ParameterizedTest
    @MethodSource("testFinanceData")
    @DisplayName("Check for exceptions when the last payment entered is incorrect.")
    void testValidateLastCreditedPaymentThrowInvalidInputDataException(String lastCredited) {
        var request = (BlockAccrualAmountRequest) firstRequest;
        request.setLastCreditedPayment(lastCredited);
        addValueThrowInvalidInputData(request);
    }

    @ParameterizedTest
    @MethodSource("testFinanceData")
    @DisplayName("Check exceptions when the entered amount to be paid is incorrect.")
    void testValidateAmountDueThrowInvalidInputDataException(String amountDue) {
        var request = (BlockAccrualAmountRequest) firstRequest;
        request.setAmountDue(amountDue);
        addValueThrowInvalidInputData(request);
    }

    private static @NonNull Stream<Arguments> testFinanceData() {
        return Stream.of(
                Arguments.of("13,5"),
                Arguments.of("ff"),
                Arguments.of("13#5")
        );
    }
}
