package org.university.payment_for_utilities.services.implementations.address;

import lombok.NonNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.university.payment_for_utilities.domains.address.AddressResidence;
import org.university.payment_for_utilities.exceptions.InvalidInputDataException;
import org.university.payment_for_utilities.pojo.requests.address.AddressResidenceRequest;
import org.university.payment_for_utilities.pojo.requests.abstract_class.Request;
import org.university.payment_for_utilities.pojo.responses.address.AddressResidenceResponse;
import org.university.payment_for_utilities.pojo.responses.abstract_class.Response;
import org.university.payment_for_utilities.repositories.address.AddressResidenceRepository;
import org.university.payment_for_utilities.services.implementations.CrudServiceAbstract;
import org.university.payment_for_utilities.services.interfaces.address.AddressResidenceService;
import org.university.payment_for_utilities.services.interfaces.company.CompanyService;

import java.util.Optional;

import static org.university.payment_for_utilities.services.implementations.tools.ExceptionTools.throwRuntimeException;

@Service
public class AddressResidenceServiceImpl extends CrudServiceAbstract<AddressResidence, AddressResidenceRepository> implements AddressResidenceService {
    private static final String NUM_HOUSE_TEMPLATE = "^[\\dA-ZА-ЯІЇҐ\\-\\s]*$";
    private static final String NUM_ENTRANCE_TEMPLATE = "^\\d{0,3}$";
    private static final String NUM_APARTMENT_TEMPLATE = "^\\d{0,5}$";

    private final CompanyService companyService;

    @Autowired
    public AddressResidenceServiceImpl(
            AddressResidenceRepository repository,
            CompanyService companyService
    ) {
        super(repository, "Addresses residence");
        this.companyService = companyService;
    }

    @Override
    protected AddressResidence createEntity(Request request) {
        var address = (AddressResidenceRequest) request;
        return AddressResidence
                .builder()
                .settlement(address.getSettlement())
                .uaNameStreet(address.getUaNameStreet())
                .enNameStreet(address.getEnNameStreet())
                .numHouse(address.getNumHouse())
                .numEntrance(address.getNumEntrance())
                .numApartment(address.getNumApartment())
                .build();
    }

    @Override
    protected AddressResidence createEntity(@NonNull Response response) {
        var addressResponse = (AddressResidenceResponse) response;
        var builder = AddressResidence.builder();
        initEntityBuilder(builder, response);

        return builder
                .settlement(addressResponse.getSettlement())
                .uaNameStreet(addressResponse.getUaNameStreet())
                .enNameStreet(addressResponse.getEnNameStreet())
                .numHouse(addressResponse.getNumHouse())
                .numEntrance(addressResponse.getNumEntrance())
                .numApartment(addressResponse.getNumApartment())
                .build();
    }

    @Override
    protected Response createResponse(@NonNull AddressResidence entity) {
        var builder = AddressResidenceResponse.builder();
        initResponseBuilder(builder, entity);

        return builder
                .settlement(entity.getSettlement())
                .uaNameStreet(entity.getUaNameStreet())
                .enNameStreet(entity.getEnNameStreet())
                .numHouse(entity.getNumHouse())
                .numEntrance(entity.getNumEntrance())
                .numApartment(entity.getNumApartment())
                .build();
    }

    @Override
    protected void deactivatedChildren(@NonNull AddressResidence entity) {
        deactivateChild(entity.getCompany(), companyService);
    }

    @Override
    protected void updateEntity(@NonNull AddressResidence entity, @NonNull Request request) {
        var newValue = (AddressResidenceRequest) request;

        if(!newValue.getSettlement().isEmpty()){
            entity.setSettlement(newValue.getSettlement());
        }
        if(!newValue.getUaNameStreet().isBlank()){
            entity.setUaNameStreet(newValue.getUaNameStreet());
        }
        if(!newValue.getEnNameStreet().isBlank()){
            entity.setEnNameStreet(newValue.getEnNameStreet());
        }
        if(!newValue.getNumHouse().isBlank()){
            entity.setNumHouse(newValue.getNumHouse());
        }
        if(!newValue.getNumEntrance().isBlank()){
            entity.setNumEntrance(newValue.getNumEntrance());
        }
        if(!newValue.getNumApartment().isBlank()){
            entity.setNumApartment(newValue.getNumApartment());
        }
    }

    @Override
    protected void validationProcedureRequest(@NonNull Request request) throws InvalidInputDataException {
        var addressRequest = (AddressResidenceRequest) request;

        validateStreet(addressRequest.getUaNameStreet());
        validateStreet(addressRequest.getEnNameStreet());
        validateNumHouse(addressRequest);
        validateNumEntrance(addressRequest);
        validateNumApartment(addressRequest);
    }

    private void validateStreet(@NonNull String name) throws InvalidInputDataException {
        if(isValidString(name)){
            return;
        }

        var message = String.format("You entered the wrong street name format: %s. The name should contain only Cyrillic and Latin letters, hyphens, and spaces.", name);
        throwRuntimeException(message, InvalidInputDataException::new);
    }

    private void validateNumHouse(@NonNull AddressResidenceRequest request) throws InvalidInputDataException {
        if(isValidNumHouse(request.getNumHouse())){
            return;
        }

        var message = String.format("You entered the wrong house number format: %s. The house number can contain Cyrillic or Latin letters, numbers, hyphens, and spaces.", request.getNumHouse());
        throwRuntimeException(message, InvalidInputDataException::new);
    }

    private boolean isValidNumHouse(@NonNull String numHouse){
        return numHouse
                .toUpperCase()
                .matches(NUM_HOUSE_TEMPLATE);
    }

    private void validateNumEntrance(@NonNull AddressResidenceRequest request) throws InvalidInputDataException {
        if(isValidNumEntrance(request.getNumEntrance())){
            return;
        }

        var message = String.format("You entered the wrong format for the entrance number: %s. The entrance number can contain no more than three digits.", request.getNumEntrance());
        throwRuntimeException(message, InvalidInputDataException::new);
    }

    private boolean isValidNumEntrance(@NonNull String numEntrance){
        return numEntrance.matches(NUM_ENTRANCE_TEMPLATE);
    }

    private void validateNumApartment(@NonNull AddressResidenceRequest request) throws InvalidInputDataException {
        if(isValidNumApartment(request.getNumApartment())){
            return;
        }

        var message = String.format("You entered the wrong apartment number format: %s. The apartment number can contain no more than five digits.", request.getNumApartment());
        throwRuntimeException(message, InvalidInputDataException::new);
    }

    private boolean isValidNumApartment(@NonNull String numApartment){
        return numApartment.matches(NUM_APARTMENT_TEMPLATE);
    }

    @Override
    protected Optional<AddressResidence> findEntity(@NonNull Request request) {
        var address = (AddressResidenceRequest) request;
        return repository
                .findBySettlementAndEnNameStreetAndNumHouseAndNumEntrance(
                        address.getSettlement(),
                        address.getEnNameStreet(),
                        address.getNumHouse(),
                        address.getNumEntrance()
                );
    }
}
