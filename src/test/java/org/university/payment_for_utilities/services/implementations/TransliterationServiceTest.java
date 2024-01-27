package org.university.payment_for_utilities.services.implementations;

import lombok.NonNull;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.boot.test.context.SpringBootTest;
import org.university.payment_for_utilities.pojo.requests.abstract_class.Request;
import org.university.payment_for_utilities.exceptions.InvalidInputDataException;
import org.university.payment_for_utilities.pojo.requests.abstract_class.TransliterationRequest;
import org.university.payment_for_utilities.services.interfaces.CrudService;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertThrows;

@SpringBootTest
public abstract class TransliterationServiceTest extends CrudServiceTest {
    protected abstract void testAddValueThrowInvalidInputData();
    protected abstract void testUpdateValueThrowInvalidInputData();

    public TransliterationServiceTest(CrudService service) {
        super(service);
    }

    protected void testAddValueThrowInvalidInputData(Request withNum, Request withSpecialCharacter) {
        addValueThrowInvalidInputData(withNum);
        addValueThrowInvalidInputData(withSpecialCharacter);
    }

    protected void testUpdateValueThrowInvalidInputData(Request incorrectRequest) {
        var response = service.addValue(firstRequest);

        assertThrows(InvalidInputDataException.class,
                () -> service.updateValue(response.getId(), incorrectRequest)
        );
    }

    @ParameterizedTest
    @MethodSource("testNamesBank")
    @DisplayName("Check for an exception when the user passed data in the wrong format to the \"uaName\" attribute.")
    void testValidateUaNameThrowInvalidInputDataException(String name){
        var request = (TransliterationRequest) firstRequest;
        request.setUaName(name);
        addValueThrowInvalidInputData(request);
    }

    @ParameterizedTest
    @MethodSource("testNamesBank")
    @DisplayName("Check for an exception when the user passed data in the wrong format to the \"enName\" attribute.")
    void testValidateEnNameThrowInvalidInputDataException(String name){
        var request = (TransliterationRequest) firstRequest;
        request.setEnName(name);
        addValueThrowInvalidInputData(request);
    }

    private static @NonNull Stream<Arguments> testNamesBank() {
        return Stream.of(
                Arguments.of("fatal@_@data"),
                Arguments.of("12345"),
                Arguments.of("name!"),
                Arguments.of("Name_with_underscore")
        );
    }
}
