package org.university.payment_for_utilities.services.implementations.user;

import lombok.NonNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.university.payment_for_utilities.domains.user.InfoAboutUser;
import org.university.payment_for_utilities.exceptions.InvalidInputDataException;
import org.university.payment_for_utilities.pojo.requests.abstract_class.Request;
import org.university.payment_for_utilities.pojo.requests.user.InfoAboutUserRequest;
import org.university.payment_for_utilities.pojo.responses.abstract_class.Response;
import org.university.payment_for_utilities.pojo.responses.user.InfoAboutUserResponse;
import org.university.payment_for_utilities.repositories.user.InfoAboutUserRepository;
import org.university.payment_for_utilities.services.implementations.CrudServiceAbstract;
import org.university.payment_for_utilities.services.interfaces.user.InfoAboutUserService;

import java.util.Optional;

@Service
public class InfoAboutUserServiceImpl extends CrudServiceAbstract<InfoAboutUser, InfoAboutUserRepository> implements InfoAboutUserService {
    @Autowired
    public InfoAboutUserServiceImpl(InfoAboutUserRepository repository) {
        super(repository, "Info about users");
    }

    @Override
    protected InfoAboutUser createEntity(Request request) {
        var infoRequest = (InfoAboutUserRequest) request;
        return InfoAboutUser
                .builder()
                .registered(infoRequest.getRegistered())
                .firstName(infoRequest.getFirstName())
                .lastName(infoRequest.getLastName())
                .build();
    }

    @Override
    protected InfoAboutUser createEntity(Response response) {
        var infoResponse = (InfoAboutUserResponse) response;
        var builder = InfoAboutUser.builder();
        initEntityBuilder(builder, infoResponse);

        return builder
                .registered(infoResponse.getRegistered())
                .firstName(infoResponse.getFirstName())
                .lastName(infoResponse.getLastName())
                .build();
    }

    @Override
    protected Response createResponse(InfoAboutUser entity) {
        var builder = InfoAboutUserResponse.builder();
        initResponseBuilder(builder, entity);

        return builder
                .registered(entity.getRegistered())
                .firstName(entity.getFirstName())
                .lastName(entity.getLastName())
                .build();
    }

    @Override
    protected void updateEntity(@NonNull InfoAboutUser entity, @NonNull Request request) {
        var newValue = (InfoAboutUserRequest) request;

        if(!newValue.getRegistered().isEmpty()){
            entity.setRegistered(newValue.getRegistered());
        }
        if(!newValue.getFirstName().isBlank()){
            entity.setFirstName(newValue.getFirstName());
        }
        if(!newValue.getLastName().isBlank()){
            entity.setLastName(newValue.getLastName());
        }
    }

    @Override
    protected void validationProcedureRequest(@NonNull Request request) throws InvalidInputDataException {
        var infoRequest = (InfoAboutUserRequest) request;

        validateName(infoRequest.getFirstName());
        validateName(infoRequest.getLastName());
    }

    @Override
    protected Optional<InfoAboutUser> findEntity(@NonNull Request request) {
        var infoRequest = (InfoAboutUserRequest) request;
        return repository
                .findByFirstNameAndLastName(
                        infoRequest.getFirstName(),
                        infoRequest.getLastName()
                );
    }
}
