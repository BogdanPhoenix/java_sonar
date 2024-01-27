package org.university.payment_for_utilities.services.implementations;

import lombok.NonNull;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.university.payment_for_utilities.exceptions.InvalidInputDataException;
import org.university.payment_for_utilities.pojo.requests.abstract_class.Request;
import org.university.payment_for_utilities.pojo.responses.abstract_class.Response;
import org.university.payment_for_utilities.exceptions.DuplicateException;
import org.university.payment_for_utilities.exceptions.EmptyRequestException;
import org.university.payment_for_utilities.exceptions.NotFindEntityInDataBaseException;
import org.university.payment_for_utilities.services.interfaces.CrudService;

import java.time.LocalDateTime;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
public abstract class CrudServiceTest {
    private final static long ID = Integer.MAX_VALUE;
    protected Request firstRequest;
    protected Request secondRequest;
    protected Request emptyRequest;
    protected CrudService service;

    protected CrudServiceTest(CrudService service) { this.service = service;}

    protected abstract void initRequest();
    protected abstract Response updateExpectedResponse(@NonNull Response response);
    protected abstract Request updateNewValue(@NonNull Response expectedResponse);

    @AfterEach
    public void clearTable(){
        service.removeAll();
    }

    @Test
    @DisplayName("Checks the output of all table entities.")
    void testGetAllEntities(){
        service.addValue(firstRequest);
        service.addValue(secondRequest);

        var entities = service.getAll();

        assertThat(entities)
                .isNotNull()
                .hasSize(2);
    }

    @Test
    @DisplayName("Check if you can retrieve an entity from a table by its identifier.")
    void testGetByIdCorrect(){
        var response = service.addValue(firstRequest);
        var responseById = service.getById(response.getId());

        assertThat(responseById)
                .isEqualTo(response);
    }

    @Test
    @DisplayName("Checks whether an exception can be thrown if you try to retrieve an entity from a table by an invalid identifier.")
    void testGetByIdThrow(){
        assertThrows(NotFindEntityInDataBaseException.class,
                () -> service.getById(ID));
    }

    @Test
    @DisplayName("Check for adding data to the database.")
    void testAddValueCorrect(){
        var response = service.addValue(firstRequest);
        assertThat(response.getId())
                .isNotNull();
    }

    @Test
    @DisplayName("Checking for an exception when the request is empty inside.")
    void testAddValueThrowRequestEmpty(){
        assertThrows(EmptyRequestException.class,
                () -> service.addValue(emptyRequest)
        );
    }

    @Test
    @DisplayName("Checking for an exception when the query passed data that already exists in the database table.")
    void testAddValueThrowDuplicate(){
        service.addValue(firstRequest);
        assertThrows(DuplicateException.class,
                () -> service.addValue(firstRequest)
        );
    }

    @Test
    @DisplayName("Checks for exceptions when the update request passes a new area name that already exists in the database table.")
    void testUpdateValueThrowDuplicate(){
        service.addValue(firstRequest);
        var response = service.addValue(secondRequest);

        assertThrows(DuplicateException.class,
                () -> service.updateValue(response.getId(), firstRequest)
        );
    }

    @Test
    @DisplayName("Checks for exceptions when a user wants to update data that is not in a database table in an update request.")
    void testUpdateValueThrowNotFindEntityInDataBase(){
        assertThrows(NotFindEntityInDataBaseException.class,
                () -> service.updateValue(ID, emptyRequest)
        );
    }

    @Test
    @DisplayName("Checking the correct deletion of data from the table using the entity identifier.")
    public void testRemoveValueByIdCorrect(){
        var responseAdd = service.addValue(firstRequest);
        var responseRemove = service.removeValue(responseAdd.getId());

        assertThat(responseAdd)
                .isEqualTo(responseRemove);
    }

    @Test
    @DisplayName("Checking the correctness of deleting data from a table using a request.")
    public void testRemoveValueByRequestCorrect(){
        var responseAdd = service.addValue(firstRequest);
        var responseRemove = service.removeValue(firstRequest);

        assertThat(responseAdd)
                .isEqualTo(responseRemove);
    }

    @Test
    @DisplayName("Checking for an exception when the user wants to delete an entity (using an entity identifier) that is not in the table.")
    void testRemoveValueByIdThrowNotFindEntityInDataBaseException(){
        assertThrows(NotFindEntityInDataBaseException.class,
                () -> service.removeValue(ID)
        );
    }

    @Test
    @DisplayName("Checking for an exception when the user wants to delete an entity (using a request) that is not in the table.")
    void testRemoveValueByRequestThrowNotFindEntityInDataBaseException(){
        assertThrows(NotFindEntityInDataBaseException.class,
                () -> service.removeValue(firstRequest)
        );
    }

    @Test
    @DisplayName("Check if all data is deleted from the table.")
    void testRemoveAll(){
        service.addValue(firstRequest);
        service.addValue(secondRequest);

        var numDeleteItems = service.removeAll();

        assertThat(numDeleteItems)
                .isEqualTo(2L);
    }

    @Test
    @DisplayName("Check if the request is empty.")
    void testRequestIsEmpty(){
        assertTrue(emptyRequest.isEmpty());
    }

    @Test
    @DisplayName("Check that the request is not empty.")
    void testRequestIsNotEmpty(){
        assertFalse(firstRequest.isEmpty());
        assertFalse(secondRequest.isEmpty());
    }

    @Test
    @DisplayName("Check if an existing entity is successfully updated in the database table.")
    protected void updateValueCorrectWithOneChangedParameter() throws InterruptedException {
        var response = service.addValue(secondRequest);
        Thread.sleep(1500L);

        var expectedResponse = updateExpectedResponse(response);
        var newValue = updateNewValue(expectedResponse);

        var updateResponse = service.updateValue(response.getId(), newValue);

        assertThat(updateResponse)
                .isEqualTo(expectedResponse)
                .isNotEqualTo(response);

        assertThat(updateResponse.getCreateDate())
                .isEqualToIgnoringNanos(response.getCreateDate());

        assertThat(updateResponse.getUpdateDate().getSecond())
                .isNotEqualTo(response.getUpdateDate().getSecond());
    }

    @Test
    @DisplayName("Check whether the values were successfully assigned to the createDate and updateDate attributes when the entity was created.")
    protected void testCreateDate(){
        var date = LocalDateTime.now();
        var response = service.addValue(firstRequest);

        assertThat(response.getCreateDate())
                .isNotNull()
                .isEqualToIgnoringNanos(response.getUpdateDate())
                .isEqualToIgnoringNanos(date);
        assertNotNull(response.getUpdateDate());
    }

    protected void addValueThrowInvalidInputData(Request request){
        assertThrows(InvalidInputDataException.class,
                () -> service.addValue(request)
        );
    }
}
