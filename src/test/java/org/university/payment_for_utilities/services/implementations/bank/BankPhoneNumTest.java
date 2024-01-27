package org.university.payment_for_utilities.services.implementations.bank;

import lombok.NonNull;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.annotation.DirtiesContext;
import org.university.payment_for_utilities.domains.bank.Bank;
import org.university.payment_for_utilities.domains.service_information_institutions.PhoneNum;
import org.university.payment_for_utilities.pojo.requests.bank.BankPhoneNumRequest;
import org.university.payment_for_utilities.pojo.requests.abstract_class.Request;
import org.university.payment_for_utilities.pojo.responses.bank.BankPhoneNumResponse;
import org.university.payment_for_utilities.pojo.responses.abstract_class.Response;
import org.university.payment_for_utilities.services.implementations.CrudServiceTest;
import org.university.payment_for_utilities.services.interfaces.bank.BankPhoneNumService;

@SpringBootTest
@Import(BankEntitiesRequestTestContextConfiguration.class)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class BankPhoneNumTest extends CrudServiceTest {
    @Autowired
    @Qualifier("privateBankPhoneNumRequest")
    private BankPhoneNumRequest privateBankPhoneNumRequest;
    @Autowired
    @Qualifier("raiffeisenBankPhoneNumRequest")
    private BankPhoneNumRequest raiffeisenBankPhoneNumRequest;
    @Autowired
    @Qualifier("updateBankPhoneNum")
    private PhoneNum updateBankPhoneNum;

    @Autowired
    public BankPhoneNumTest(BankPhoneNumService service) { super(service); }

    @BeforeEach
    @Override
    protected void initRequest() {
        firstRequest = privateBankPhoneNumRequest;
        secondRequest = raiffeisenBankPhoneNumRequest;
        emptyRequest = BankPhoneNumRequest
                .empty();
    }

    @Override
    protected Response updateExpectedResponse(@NonNull Response response) {
        return BankPhoneNumResponse
                .builder()
                .id(response.getId())
                .bank(raiffeisenBankPhoneNumRequest.getBank())
                .phoneNum(updateBankPhoneNum)
                .build();
    }

    @Override
    protected Request updateNewValue(@NonNull Response expectedResponse) {
        var response = (BankPhoneNumResponse) expectedResponse;
        return BankPhoneNumRequest
                .builder()
                .bank(Bank.empty())
                .phoneNum(response.getPhoneNum())
                .build();
    }
}
