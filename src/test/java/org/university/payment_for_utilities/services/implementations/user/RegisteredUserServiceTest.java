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
import org.university.payment_for_utilities.domains.service_information_institutions.PhoneNum;
import org.university.payment_for_utilities.enumarations.Role;
import org.university.payment_for_utilities.pojo.requests.abstract_class.Request;
import org.university.payment_for_utilities.pojo.requests.user.RegisteredUserRequest;
import org.university.payment_for_utilities.pojo.responses.abstract_class.Response;
import org.university.payment_for_utilities.pojo.responses.user.RegisterUserResponse;
import org.university.payment_for_utilities.services.implementations.CrudServiceTest;
import org.university.payment_for_utilities.services.interfaces.user.RegisteredUserService;

import java.util.stream.Stream;

@SpringBootTest
@Import(UserEntitiesRequestTestContextConfiguration.class)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class RegisteredUserServiceTest extends CrudServiceTest {
    @Autowired
    @Qualifier("registeredUserIvanRequest")
    private RegisteredUserRequest userIvanRequest;
    @Autowired
    @Qualifier("registeredUserOlegRequest")
    private RegisteredUserRequest userOlegRequest;

    @Autowired
    public RegisteredUserServiceTest(RegisteredUserService service) { super(service); }

    @BeforeEach
    @Override
    protected void initRequest() {
        firstRequest = userIvanRequest;
        secondRequest = userOlegRequest;
        emptyRequest = RegisteredUserRequest
                .empty();
    }

    @Override
    protected Response updateExpectedResponse(@NonNull Response response) {
        return RegisterUserResponse
                .builder()
                .id(response.getId())
                .username("update@gmail.com")
                .password("newpaSs@o4d")
                .role(Role.BANK_ADMIN)
                .phoneNum(userOlegRequest.getPhoneNum())
                .build();
    }

    @Override
    protected Request updateNewValue(@NonNull Response expectedResponse) {
        var response = (RegisterUserResponse) expectedResponse;
        return RegisteredUserRequest
                .builder()
                .username(response.getUsername())
                .password(response.getPassword())
                .role(response.getRole())
                .phoneNum(PhoneNum.empty())
                .build();
    }

    @ParameterizedTest
    @MethodSource("testUserEmails")
    @DisplayName("Check exceptions if the request has an incorrect email format.")
    void testValidateUserEmailThrowInvalidInputDataException(String email) {
        var request = (RegisteredUserRequest) firstRequest;
        request.setUsername(email);
        addValueThrowInvalidInputData(request);
    }

    private static @NonNull Stream<Arguments> testUserEmails() {
        return Stream.of(
                Arguments.of("test_gmail.com"),
                Arguments.of("test@gmailcom"),
                Arguments.of("test@gmail_com"),
                Arguments.of("test1gmail.com")
        );
    }

    @ParameterizedTest
    @MethodSource("testPasswords")
    @DisplayName("Check exceptions if the request has an incorrect password format.")
    void testValidatePasswordThrowInvalidInputDataException(String password) {
        var request = (RegisteredUserRequest) firstRequest;
        request.setPassword(password);
        addValueThrowInvalidInputData(request);
    }

    private static @NonNull Stream<Arguments> testPasswords() {
        return Stream.of(
                Arguments.of("qwE@t1"),
                Arguments.of("qwertyui"),
                Arguments.of("qwe3#yui"),
                Arguments.of("qWert4tdfgd")
        );
    }
}
