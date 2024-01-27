package org.university.payment_for_utilities.services.implementations.user;

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
import org.university.payment_for_utilities.domains.user.RegisteredUser;
import org.university.payment_for_utilities.pojo.requests.abstract_class.Request;
import org.university.payment_for_utilities.pojo.requests.user.InfoAboutUserRequest;
import org.university.payment_for_utilities.pojo.responses.abstract_class.Response;
import org.university.payment_for_utilities.pojo.responses.user.InfoAboutUserResponse;
import org.university.payment_for_utilities.services.implementations.CrudServiceTest;
import org.university.payment_for_utilities.services.interfaces.user.InfoAboutUserService;

import java.util.stream.Stream;

@SpringBootTest
@Import(UserEntitiesRequestTestContextConfiguration.class)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class InfoAboutUserServiceTest extends CrudServiceTest {
    @Autowired
    @Qualifier("userIvanRequest")
    private InfoAboutUserRequest userIvanRequest;
    @Autowired
    @Qualifier("userOlegRequest")
    private InfoAboutUserRequest userOlegRequest;

    @Autowired
    public InfoAboutUserServiceTest (InfoAboutUserService service) { super(service); }

    @BeforeEach
    @Override
    protected void initRequest() {
        firstRequest = userIvanRequest;
        secondRequest = userOlegRequest;
        emptyRequest = InfoAboutUserRequest
                .empty();
    }

    @Override
    protected Response updateExpectedResponse(@NonNull Response response) {
        return InfoAboutUserResponse
                .builder()
                .id(response.getId())
                .registered(userOlegRequest.getRegistered())
                .firstName("Petro")
                .lastName("Petro")
                .build();
    }

    @Override
    protected Request updateNewValue(@NonNull Response expectedResponse) {
        var response = (InfoAboutUserResponse) expectedResponse;
        return InfoAboutUserRequest
                .builder()
                .registered(RegisteredUser.empty())
                .firstName(response.getFirstName())
                .lastName(response.getLastName())
                .build();
    }

    @ParameterizedTest
    @MethodSource("testFirstNames")
    @DisplayName("Check exceptions if the request has an incorrect first name format.")
    void testValidateFirstNameThrowInvalidInputDataException(String firstName) {
        var request = (InfoAboutUserRequest) firstRequest;
        request.setFirstName(firstName);
        addValueThrowInvalidInputData(request);
    }

    private static @NonNull Stream<Arguments> testFirstNames() {
        return Stream.of(
                Arguments.of("Ivan#"),
                Arguments.of("Iva5n")
        );
    }

    @ParameterizedTest
    @MethodSource("testPasswords")
    @DisplayName("Check exceptions if the request has an incorrect last name format.")
    void testValidateLastNameThrowInvalidInputDataException(String lastName) {
        var request = (InfoAboutUserRequest) firstRequest;
        request.setLastName(lastName);
        addValueThrowInvalidInputData(request);
    }

    private static @NonNull Stream<Arguments> testPasswords() {
        return Stream.of(
                Arguments.of("Ivanov#"),
                Arguments.of("Iva5nov")
        );
    }
}
