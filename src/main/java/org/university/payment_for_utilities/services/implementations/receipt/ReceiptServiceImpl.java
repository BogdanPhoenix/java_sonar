package org.university.payment_for_utilities.services.implementations.receipt;

import lombok.NonNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.university.payment_for_utilities.domains.receipt.Receipt;
import org.university.payment_for_utilities.exceptions.InvalidInputDataException;
import org.university.payment_for_utilities.pojo.requests.abstract_class.Request;
import org.university.payment_for_utilities.pojo.requests.receipt.ReceiptRequest;
import org.university.payment_for_utilities.pojo.responses.abstract_class.Response;
import org.university.payment_for_utilities.pojo.responses.receipt.ReceiptResponse;
import org.university.payment_for_utilities.repositories.receipt.ReceiptRepository;
import org.university.payment_for_utilities.services.implementations.CrudServiceAbstract;
import org.university.payment_for_utilities.services.interfaces.receipt.BlockAccrualAmountService;
import org.university.payment_for_utilities.services.interfaces.receipt.BlockMeterReadingService;
import org.university.payment_for_utilities.services.interfaces.receipt.PaymentHistoryService;
import org.university.payment_for_utilities.services.interfaces.receipt.ReceiptService;

import java.time.LocalDate;
import java.time.Period;
import java.util.Optional;

import static org.university.payment_for_utilities.services.implementations.tools.ExceptionTools.throwRuntimeException;

@Service
public class ReceiptServiceImpl extends CrudServiceAbstract<Receipt, ReceiptRepository> implements ReceiptService {
    private static final int MAX_DIFFERENCE_MONTHS = 1;

    private final PaymentHistoryService paymentHistoryService;
    private final BlockAccrualAmountService blockAccrualAmountService;
    private final BlockMeterReadingService blockMeterReadingService;

    @Autowired
    public ReceiptServiceImpl(
            ReceiptRepository repository,
            PaymentHistoryService paymentHistoryService,
            BlockAccrualAmountService blockAccrualAmountService,
            BlockMeterReadingService blockMeterReadingService
    ) {
        super(repository, "Receipts");
        this.paymentHistoryService = paymentHistoryService;
        this.blockAccrualAmountService = blockAccrualAmountService;
        this.blockMeterReadingService = blockMeterReadingService;
    }

    @Override
    protected Receipt createEntity(Request request) {
        var receiptRequest = (ReceiptRequest) request;
        return Receipt
                .builder()
                .contractEntity(receiptRequest.getContractEntity())
                .bank(receiptRequest.getBank())
                .billMonth(receiptRequest.getBillMonth())
                .build();
    }

    @Override
    protected Receipt createEntity(Response response) {
        var receiptResponse = (ReceiptResponse) response;
        var builder = Receipt.builder();
        initEntityBuilder(builder, response);

        return builder
                .contractEntity(receiptResponse.getContractEntity())
                .bank(receiptResponse.getBank())
                .billMonth(receiptResponse.getBillMonth())
                .build();
    }

    @Override
    protected Response createResponse(Receipt entity) {
        var builder = ReceiptResponse.builder();
        initResponseBuilder(builder, entity);

        return builder
                .contractEntity(entity.getContractEntity())
                .bank(entity.getBank())
                .billMonth(entity.getBillMonth())
                .build();
    }

    @Override
    protected void deactivatedChildren(@NonNull Receipt entity) {
        deactivateChildrenCollection(entity.getPaymentHistories(), paymentHistoryService);
        deactivateChildrenCollection(entity.getBlockAccrualAmounts(), blockAccrualAmountService);
        deactivateChildrenCollection(entity.getBlockMeterReadings(), blockMeterReadingService);
    }

    @Override
    protected void updateEntity(@NonNull Receipt entity, @NonNull Request request) {
        var newValue = (ReceiptRequest) request;

        if(!newValue.getContractEntity().isEmpty()){
            entity.setContractEntity(newValue.getContractEntity());
        }
        if(!newValue.getBank().isEmpty()){
            entity.setBank(newValue.getBank());
        }
        if(!newValue.getBillMonth().equals(LocalDate.MIN)){
            entity.setBillMonth(newValue.getBillMonth());
        }
    }

    @Override
    protected void validationProcedureRequest(@NonNull Request request) throws InvalidInputDataException {
        var receiptRequest = (ReceiptRequest) request;
        validateBillMonth(receiptRequest.getBillMonth());
    }

    private void validateBillMonth(@NonNull LocalDate billMonth) throws InvalidInputDataException {
        if(isBillMonth(billMonth)) {
            return;
        }

        var message = String.format("The month and year you entered: \"%s\" has not been validated. The difference between the specified month and the current month should not be more than %s month(s).", billMonth, MAX_DIFFERENCE_MONTHS);
        throwRuntimeException(message, InvalidInputDataException::new);
    }

    private boolean isBillMonth(@NonNull LocalDate billMonth) {
        var period = Period.between(billMonth, LocalDate.now());
        var monthDifference = period.getYears() * 12 + period.getMonths();
        return Math.abs(monthDifference) <= MAX_DIFFERENCE_MONTHS;
    }

    @Override
    protected Optional<Receipt> findEntity(@NonNull Request request) {
        var receiptRequest = (ReceiptRequest) request;
        return repository
                .findByContractEntityAndBankAndBillMonth(
                        receiptRequest.getContractEntity(),
                        receiptRequest.getBank(),
                        receiptRequest.getBillMonth()
                );
    }
}
