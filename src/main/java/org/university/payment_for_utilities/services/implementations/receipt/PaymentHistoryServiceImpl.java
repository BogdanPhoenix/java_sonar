package org.university.payment_for_utilities.services.implementations.receipt;

import lombok.NonNull;
import org.springframework.stereotype.Service;
import org.university.payment_for_utilities.domains.receipt.PaymentHistory;
import org.university.payment_for_utilities.exceptions.InvalidInputDataException;
import org.university.payment_for_utilities.pojo.requests.abstract_class.Request;
import org.university.payment_for_utilities.pojo.requests.receipt.PaymentHistoryRequest;
import org.university.payment_for_utilities.pojo.responses.abstract_class.Response;
import org.university.payment_for_utilities.pojo.responses.receipt.PaymentHistoryResponse;
import org.university.payment_for_utilities.repositories.receipt.PaymentHistoryRepository;
import org.university.payment_for_utilities.services.implementations.auxiliary_services.CounterSearcherService;
import org.university.payment_for_utilities.services.interfaces.receipt.PaymentHistoryService;

import static org.university.payment_for_utilities.services.implementations.tools.FinanceTools.convertStringToBigDecimal;
import static org.university.payment_for_utilities.services.implementations.tools.FinanceTools.validateFinance;

@Service
public class PaymentHistoryServiceImpl extends CounterSearcherService<PaymentHistory, PaymentHistoryRepository> implements PaymentHistoryService {
    protected PaymentHistoryServiceImpl(PaymentHistoryRepository repository) {
        super(repository, "Payment history");
    }

    @Override
    protected PaymentHistory createEntity(Request request) {
        var historyRequest = (PaymentHistoryRequest) request;
        var payment = convertStringToBigDecimal(historyRequest.getFinalPaymentAmount());
        return PaymentHistory
                .builder()
                .receipt(historyRequest.getReceipt())
                .prevValueCounter(historyRequest.getPrevValueCounter())
                .currentValueCounter(historyRequest.getCurrentValueCounter())
                .finalPaymentAmount(payment)
                .build();
    }

    @Override
    protected PaymentHistory createEntity(Response response) {
        var historyResponse = (PaymentHistoryResponse) response;
        var builder = PaymentHistory.builder();
        super.initCounterSearcherBuilder(builder, response);

        return builder
                .finalPaymentAmount(historyResponse.getFinalPaymentAmount())
                .build();
    }

    @Override
    protected Response createResponse(PaymentHistory entity) {
        var builder = PaymentHistoryResponse.builder();
        super.initCounterResponseBuilder(builder, entity);

        return builder
                .finalPaymentAmount(entity.getFinalPaymentAmount())
                .build();
    }

    @Override
    protected void updateEntity(@NonNull PaymentHistory entity, @NonNull Request request) {
        super.updateEntity(entity, request);
        var newValue = (PaymentHistoryRequest) request;

        if(!newValue.getFinalPaymentAmount().isBlank()){
            var payment = convertStringToBigDecimal(newValue.getFinalPaymentAmount());
            entity.setFinalPaymentAmount(payment);
        }
    }

    @Override
    protected void validationProcedureRequest(@NonNull Request request) throws InvalidInputDataException {
        super.validationProcedureRequest(request);
        var historyRequest = (PaymentHistoryRequest) request;
        validateFinance("final payment amount", historyRequest.getFinalPaymentAmount());
    }
}
