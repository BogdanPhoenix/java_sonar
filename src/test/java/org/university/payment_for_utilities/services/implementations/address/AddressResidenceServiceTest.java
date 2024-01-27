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
import org.university.payment_for_utilities.domains.address.Settlement;
import org.university.payment_for_utilities.pojo.requests.address.AddressResidenceRequest;
import org.university.payment_for_utilities.pojo.requests.abstract_class.Request;
import org.university.payment_for_utilities.pojo.responses.address.AddressResidenceResponse;
import org.university.payment_for_utilities.pojo.responses.abstract_class.Response;
import org.university.payment_for_utilities.services.implementations.CrudServiceTest;
import org.university.payment_for_utilities.services.interfaces.address.AddressResidenceService;

@SpringBootTest
@Import(AddressEntitiesRequestTestContextConfiguration.class)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class AddressResidenceServiceTest extends CrudServiceTest {
    @Autowired
    @Qualifier("addressRivneRequest")
    private AddressResidenceRequest addressRequest;
    @Autowired
    @Qualifier("addressKyivRequest")
    private AddressResidenceRequest addressKyivRequest;

    @Autowired
    public AddressResidenceServiceTest(AddressResidenceService service){
        super(service);
    }

    @BeforeEach
    @Override
    protected void initRequest() {
        firstRequest = addressRequest;
        secondRequest = addressKyivRequest;
        emptyRequest = AddressResidenceRequest
                .empty();
    }

    @Override
    protected Response updateExpectedResponse(@NonNull Response response){
        return AddressResidenceResponse
                .builder()
                .id(response.getId())
                .settlement(addressKyivRequest.getSettlement())
                .uaNameStreet("вулиця нова")
                .enNameStreet("new street")
                .numHouse("41")
                .numEntrance("5")
                .numApartment("305")
                .build();

    }

    @Override
    protected Request updateNewValue(@NonNull Response expectedResponse){
        var response = (AddressResidenceResponse) expectedResponse;
        return AddressResidenceRequest
                .builder()
                .settlement(Settlement.empty())
                .uaNameStreet("")
                .enNameStreet("")
                .numHouse(response.getNumHouse())
                .numEntrance(response.getNumEntrance())
                .numApartment(response.getNumApartment())
                .build();
    }

    @Test
    @DisplayName("Check for an exception when the user passed data in the wrong format to the \"uaNameStreet\" attribute.")
    void testValidateUaNameStreetThrowInvalidInputDataException(){
        var request = (AddressResidenceRequest) firstRequest;
        request.setUaNameStreet("хибні@_@дані");
        addValueThrowInvalidInputData(request);
    }

    @Test
    @DisplayName("Check for an exception when the user passed data in the wrong format to the \"enNameStreet\" attribute.")
    void testValidateEnNameStreetThrowInvalidInputDataException(){
        var request = (AddressResidenceRequest) firstRequest;
        request.setEnNameStreet("fatal@_@data");
        addValueThrowInvalidInputData(request);
    }

    @Test
    @DisplayName("Check for an exception when the user passed data in the wrong format to the \"numHouse\" attribute.")
    void testValidateNumHouseThrowInvalidInputDataException(){
        var request = (AddressResidenceRequest) firstRequest;
        request.setNumHouse("5@B");
        addValueThrowInvalidInputData(request);
    }

    @Test
    @DisplayName("Check for an exception when the user passed data in the wrong format to the \"numEntrance\" attribute.")
    void testValidateNumEntranceThrowInvalidInputDataException(){
        var request = (AddressResidenceRequest) firstRequest;
        request.setNumEntrance("B");
        addValueThrowInvalidInputData(request);
    }

    @Test
    @DisplayName("Check for an exception when the user passed data in the wrong format to the \"numApartment\" attribute.")
    void testValidateNumApartmentThrowInvalidInputDataException(){
        var request = (AddressResidenceRequest) firstRequest;
        request.setNumApartment("test");
        addValueThrowInvalidInputData(request);
    }
}
