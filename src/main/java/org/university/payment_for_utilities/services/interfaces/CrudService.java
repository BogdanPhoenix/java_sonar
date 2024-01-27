package org.university.payment_for_utilities.services.interfaces;

import lombok.NonNull;
import org.university.payment_for_utilities.pojo.requests.abstract_class.Request;
import org.university.payment_for_utilities.pojo.responses.abstract_class.Response;
import org.university.payment_for_utilities.exceptions.DuplicateException;
import org.university.payment_for_utilities.exceptions.EmptyRequestException;
import org.university.payment_for_utilities.exceptions.InvalidInputDataException;
import org.university.payment_for_utilities.exceptions.NotFindEntityInDataBaseException;

import java.util.List;

public interface CrudService {
    /**
     * Provides the entire contents of the table.
     * @return all entities of the table; never {@literal null}.
     */
    List<Response> getAll();

    /**
     * Returns the entity by the specified identifier.
     *
     * @param id must not be {@literal null}.
     * @return the table entity.
     */
    Response getById(Long id) throws NotFindEntityInDataBaseException;

    /**
     * Creates an object according to the specified request.
     *
     * @param request must not be {@literal null}.
     * @return response for the saved entity; never {@literal null}.
     * @throws EmptyRequestException if the variables of the given entity are {@literal null} or {@literal empty}.
     * @throws InvalidInputDataException if the variables of this entity have an incorrect data format.
     * @throws DuplicateException if the table contains an entity value that is passed in the query.
     */
    Response addValue(@NonNull Request request) throws EmptyRequestException, InvalidInputDataException, DuplicateException;

    /**
     * Updates the value of an entity in a database table.
     *
     * @param id identifier of the current entity {@literal null}
     * @param request must not be {@literal null}.
     * @return response for the updated entity; never {@literal null}.
     * @throws EmptyRequestException if the variables of the given entity are {@literal null} or {@literal empty}.
     * @throws InvalidInputDataException if the variables of this entity have an incorrect data format.
     * @throws DuplicateException if the table contains an entity value by which you want to update the value of the current entity.
     * @throws NotFindEntityInDataBaseException if the table does not contain the entity you want to update.
     */
    Response updateValue(@NonNull Long id, @NonNull Request request) throws EmptyRequestException, InvalidInputDataException, DuplicateException, NotFindEntityInDataBaseException;

    /**
     * Removes an entity from the table by the specified identifier.
     *
     * @param id must not be {@literal null}.
     * @return response for the deleted entity; never {@literal null}.
     * @throws NotFindEntityInDataBaseException if the table does not contain the entity to be deleted.
     */
    Response removeValue(Long id) throws NotFindEntityInDataBaseException;

    /**
     * Deletes an entity from the table by the specified query.
     *
     * @param request must not be {@literal null}.
     * @return response for the deleted entity; never {@literal null}.
     * @throws NotFindEntityInDataBaseException if the table does not contain the entity to be deleted.
     */
    Response removeValue(@NonNull Request request) throws NotFindEntityInDataBaseException;

    /**
     * Deletes all entities from the table.
     *
     * @return the number of deleted entities.
     */
    Long removeAll();
}
