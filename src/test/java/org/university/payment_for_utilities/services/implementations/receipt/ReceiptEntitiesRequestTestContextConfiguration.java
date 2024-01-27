package org.university.payment_for_utilities.services.implementations.receipt;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Lazy;
import org.university.payment_for_utilities.configurations.database.DataBaseConfiguration;
import org.university.payment_for_utilities.domains.bank.Bank;
import org.university.payment_for_utilities.domains.receipt.Receipt;
import org.university.payment_for_utilities.domains.user.ContractEntity;
import org.university.payment_for_utilities.pojo.requests.receipt.BlockAccrualAmountRequest;
import org.university.payment_for_utilities.pojo.requests.receipt.BlockMeterReadingRequest;
import org.university.payment_for_utilities.pojo.requests.receipt.PaymentHistoryRequest;
import org.university.payment_for_utilities.pojo.requests.receipt.ReceiptRequest;
import org.university.payment_for_utilities.services.implementations.bank.BankEntitiesRequestTestContextConfiguration;
import org.university.payment_for_utilities.services.implementations.user.UserEntitiesRequestTestContextConfiguration;

import java.time.LocalDate;

import static org.university.payment_for_utilities.AdditionalTestingTools.createEntity;

@TestConfiguration
@ComponentScan(basePackages = "org.university.payment_for_utilities.services.implementations.receipt")
@Import({
        DataBaseConfiguration.class,
        BankEntitiesRequestTestContextConfiguration.class,
        UserEntitiesRequestTestContextConfiguration.class
})
public class ReceiptEntitiesRequestTestContextConfiguration {
    @Autowired
    private ReceiptServiceImpl receiptService;

    @Autowired
    @Qualifier("privateBank")
    private Bank privateBank;
    @Autowired
    @Qualifier("raiffeisenBank")
    private Bank raiffeisenBank;
    @Autowired
    @Qualifier("rivneContract")
    private ContractEntity rivneContract;
    @Autowired
    @Qualifier("kyivContract")
    private ContractEntity kyivContract;

    @Lazy
    @Bean(name = "rivneAccrualAmountRequest")
    public BlockAccrualAmountRequest rivneAccrualAmountRequest() {
        var receipt = createReceipt(rivneReceiptRequest());

        return BlockAccrualAmountRequest
                .builder()
                .receipt(receipt)
                .debtBeginMonth("124")
                .debtEndMonth("10")
                .fine("50.05")
                .lastCreditedPayment("420.5")
                .amountDue("656")
                .build();
    }

    @Lazy
    @Bean(name = "rivneBlockMeter")
    public BlockMeterReadingRequest rivneBlockMeter() {
        var receipt = createReceipt(rivneReceiptRequest());

        return BlockMeterReadingRequest
                .builder()
                .receipt(receipt)
                .prevValueCounter(4231.5f)
                .currentValueCounter(4321f)
                .build();
    }

    @Lazy
    @Bean(name = "rivnePaymentHistoryRequest")
    public PaymentHistoryRequest rivnePaymentHistoryRequest() {
        var receipt = createReceipt(rivneReceiptRequest());

        return PaymentHistoryRequest
                .builder()
                .receipt(receipt)
                .prevValueCounter(1f)
                .currentValueCounter(34f)
                .finalPaymentAmount("420.32")
                .build();
    }

    @Lazy
    @Bean(name = "rivneReceiptRequest")
    public ReceiptRequest rivneReceiptRequest() {
        return ReceiptRequest
                .builder()
                .contractEntity(rivneContract)
                .bank(privateBank)
                .billMonth(LocalDate.now())
                .build();
    }

    @Lazy
    @Bean(name = "kyivAccrualAmountRequest")
    public BlockAccrualAmountRequest kyivAccrualAmountRequest() {
        var receipt = createReceipt(kyivReceiptRequest());

        return BlockAccrualAmountRequest
                .builder()
                .receipt(receipt)
                .debtBeginMonth("452")
                .debtEndMonth("120")
                .fine("120.05")
                .lastCreditedPayment("356.50")
                .amountDue("512.00")
                .build();
    }

    @Lazy
    @Bean(name = "kyivBlockMeter")
    public BlockMeterReadingRequest kyivBlockMeter() {
        var receipt = createReceipt(kyivReceiptRequest());

        return BlockMeterReadingRequest
                .builder()
                .receipt(receipt)
                .prevValueCounter(41.9f)
                .currentValueCounter(60.1f)
                .build();
    }

    @Lazy
    @Bean(name = "kyivPaymentHistoryRequest")
    public PaymentHistoryRequest kyivPaymentHistoryRequest() {
        var receipt = createReceipt(kyivReceiptRequest());

        return PaymentHistoryRequest
                .builder()
                .receipt(receipt)
                .prevValueCounter(1243f)
                .currentValueCounter(1450f)
                .finalPaymentAmount("520.5")
                .build();
    }

    @Lazy
    @Bean(name = "kyivReceiptRequest")
    public ReceiptRequest kyivReceiptRequest() {
        return ReceiptRequest
                .builder()
                .contractEntity(kyivContract)
                .bank(raiffeisenBank)
                .billMonth(LocalDate.now())
                .build();
    }

    private Receipt createReceipt(ReceiptRequest request) {
        return (Receipt) createEntity(receiptService, request);
    }
}
