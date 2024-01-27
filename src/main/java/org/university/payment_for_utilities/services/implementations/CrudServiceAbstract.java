package org.university.payment_for_utilities.services.implementations;

import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.Contract;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.transaction.annotation.Transactional;
import org.university.payment_for_utilities.domains.abstract_class.TableInfo;
import org.university.payment_for_utilities.exceptions.DuplicateException;
import org.university.payment_for_utilities.exceptions.EmptyRequestException;
import org.university.payment_for_utilities.exceptions.InvalidInputDataException;
import org.university.payment_for_utilities.exceptions.NotFindEntityInDataBaseException;
import org.university.payment_for_utilities.pojo.requests.abstract_class.Request;
import org.university.payment_for_utilities.pojo.responses.abstract_class.Response;
import org.university.payment_for_utilities.services.interfaces.CrudService;
import org.university.payment_for_utilities.domains.abstract_class.TableInfo.TableInfoBuilder;
import org.university.payment_for_utilities.pojo.responses.abstract_class.Response.ResponseBuilder;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import static org.university.payment_for_utilities.services.implementations.tools.ExceptionTools.throwNotFindEntityInDataBaseException;
import static org.university.payment_for_utilities.services.implementations.tools.ExceptionTools.throwRuntimeException;

@Slf4j
public abstract class CrudServiceAbstract<T extends TableInfo, J extends JpaRepository<T, Long>> implements CrudService {
    protected static final String MESSAGE_SUCCESS_VALIDATION = "The %s method was executed successfully.";
    protected static final String MESSAGE_INPUT_TO_METHOD = "Input to the %s method";
    protected static final String METHOD_NAME = "%s.%s";
    private static final String NAME_TEMPLATE = "^[A-ZА-ЯІЇҐ\\-.\\s]*$";

    protected final String fatalMessageAddEntity;
    protected final String fatalMessageUpdateEntity;
    protected final String fatalMessageFindOldEntity;
    private final String nameClass;

    protected J repository;
    protected String tableName;

    protected CrudServiceAbstract(J repository, String tableName) {
        this.repository = repository;
        this.tableName = tableName;

        fatalMessageAddEntity = String.format("You sent an empty request when trying to add a new record to the \"%s\" table.", tableName);
        fatalMessageUpdateEntity = String.format("You sent an empty query in the \"oldValue\" field when trying to update a record in the \"%s\" table.", tableName);
        fatalMessageFindOldEntity = String.format("Failed to find an entity in the \"%s\" table by the old value when updating the table entity.", tableName);
        nameClass = this.getClass().getSimpleName();
    }

    protected static <R extends TableInfo> void deactivateChildrenCollection(List<R> collection, CrudService service){
        Optional.ofNullable(collection)
                .ifPresent(collect ->
                        collect
                                .forEach(
                                        settlement ->
                                                service.removeValue(settlement.getId())
                                )
                );
    }

    protected static void deactivateChild(TableInfo child, CrudService service) {
        Optional.ofNullable(child)
                .ifPresent(entity ->
                        service.removeValue(entity.getId())
                );
    }

    protected void initEntityBuilder(@NonNull TableInfoBuilder<?,?> builder, @NonNull Response response) {
        builder.id(response.getId())
                .createDate(response.getCreateDate())
                .updateDate(response.getUpdateDate())
                .currentData(true);
    }

    protected void initResponseBuilder(@NonNull ResponseBuilder<?, ?> builder, @NonNull T entity) {
        builder.id(entity.getId())
                .createDate(entity.getCreateDate())
                .updateDate(entity.getUpdateDate());
    }

    @Transactional(readOnly = true)
    @Override
    public List<Response> getAll(){
        return findAll()
                .stream()
                .map(this::createResponse)
                .toList();
    }

    @Transactional(readOnly = true)
    @Override
    public Response getById(Long id) throws NotFindEntityInDataBaseException{
        var entity = findById(id);
        return createResponse(entity);
    }

    @Transactional
    @Override
    public Response addValue(@NonNull Request request) throws EmptyRequestException, InvalidInputDataException, DuplicateException {
        validateAdd(request);

        var newEntity = createEntity(request);
        var result = repository.save(newEntity);

        return createResponse(result);
    }

    protected void validateAdd(@NonNull Request request) throws EmptyRequestException, InvalidInputDataException, DuplicateException {
        var methodName = String.format(METHOD_NAME, nameClass, "addValue(Request request)");
        log.info(String.format(MESSAGE_INPUT_TO_METHOD, methodName));

        validateRequestEmpty(request, fatalMessageAddEntity);
        validationProcedureRequest(request);
        validateDuplicate(request);

        log.info(String.format(MESSAGE_SUCCESS_VALIDATION, methodName));
    }

    @Transactional
    @Override
    public Response updateValue(@NonNull Long id, @NonNull Request request) throws EmptyRequestException, InvalidInputDataException, DuplicateException, NotFindEntityInDataBaseException {
        var entity = findById(id);
        validateUpdate(request);

        updateEntity(entity, request);
        entity.setUpdateDate(LocalDateTime.now());
        var result = repository.save(entity);

        return createResponse(result);
    }

    protected void validateUpdate(@NonNull Request request) throws EmptyRequestException, InvalidInputDataException, DuplicateException {
        var methodName = String.format(METHOD_NAME, nameClass, "updateValue(Request request)");
        log.info(String.format(MESSAGE_INPUT_TO_METHOD, methodName));

        validationProcedureRequest(request);
        validateDuplicate(request);

        log.info(String.format(MESSAGE_SUCCESS_VALIDATION, methodName));
    }

    @Transactional
    @Override
    public Response removeValue(@NonNull Request request) throws NotFindEntityInDataBaseException {
        var methodName = String.format(METHOD_NAME, nameClass, "removeValue(Request request)");
        log.info(String.format(MESSAGE_INPUT_TO_METHOD, methodName));

        var entity = findOldEntity(request)
                .orElseThrow(() -> {
                        var message = String.format("Could not find an entity in table \"%s\" for the specified query: %s.", tableName, request);
                        return throwNotFindEntityInDataBaseException(message);
                    }
                );

        removeEntity(entity);

        log.info(String.format(MESSAGE_SUCCESS_VALIDATION, methodName));
        return createResponse(entity);
    }

    @Transactional
    @Override
    public Response removeValue(Long id) throws NotFindEntityInDataBaseException {
        var methodName = String.format(METHOD_NAME, nameClass, "removeValue(Long id)");
        log.info(String.format(MESSAGE_INPUT_TO_METHOD, methodName));

        var entity = findById(id);
        removeEntity(entity);

        log.info(String.format(MESSAGE_SUCCESS_VALIDATION, methodName));
        return createResponse(entity);
    }

    @Transactional
    @Override
    public Long removeAll() {
        var methodName = String.format(METHOD_NAME, nameClass, "removeAll()");
        log.info(String.format(MESSAGE_INPUT_TO_METHOD, methodName));

        var numDeleteItems = repository.count();
        findAll().forEach(this::removeEntity);

        log.info(String.format(MESSAGE_SUCCESS_VALIDATION, methodName));
        return numDeleteItems;
    }

    private List<T> findAll() {
        return repository
                .findAll()
                .stream()
                .filter(TableInfo::isCurrentData)
                .toList();
    }

    protected T findById(@NonNull Long id) throws NotFindEntityInDataBaseException {
        return repository
                .findById(id)
                .filter(TableInfo::isCurrentData)
                .orElseThrow(() -> {
                            var message = String.format("Unable to find an entity in the \"%s\" table using the specified identifier: %d.", tableName, id);
                            return throwNotFindEntityInDataBaseException(message);
                        }
                );
    }

    private void removeEntity(@NonNull T entity){
        entity.setCurrentData(false);
        entity.setUpdateDate(LocalDateTime.now());
        repository.save(entity);
        deactivatedChildren(entity);
    }

    protected void deactivatedChildren(@NonNull T entity){
        //TODO It is not required in all classes. I am a basic stub for all classes
    }

    protected void validateRequestEmpty(Request request, String message) throws EmptyRequestException {
        if(!isRequestEmpty(request)){
            return;
        }

        throwRuntimeException(message, EmptyRequestException::new);
    }

    private boolean isRequestEmpty(Request request){
        return request == null || request.isEmpty();
    }

    protected void validateDuplicate(@NonNull Request request) throws DuplicateException {
        if(!isDuplicate(request)){
            return;
        }

        var message = String.format("The \"%s\" entity is already present in the \"%s\" table.", request, tableName);
        throwRuntimeException(message, DuplicateException::new);
    }

    protected boolean isDuplicate(@NonNull Request request){
        return !request.isEmpty() && findEntity(request)
                .isPresent();
    }

    private Optional<T> findOldEntity(@NonNull Request request){
        return findEntity(request)
                .filter(TableInfo::isCurrentData);
    }

    protected void validateName(@NonNull String name) throws InvalidInputDataException{
        if(isValidString(name)){
            return;
        }

        var message = String.format("The data in the %s query should contain only Cyrillic and Latin letters, hyphens, and spaces.", name);
        throwRuntimeException(message, InvalidInputDataException::new);
    }

    @Contract(pure = true)
    protected boolean isValidString(@NonNull String name) {
        return name
                .toUpperCase()
                .matches(NAME_TEMPLATE);
    }

    protected abstract T createEntity(Request request);
    protected abstract T createEntity(Response response);
    protected abstract Response createResponse(T entity);
    protected abstract void updateEntity(@NonNull T entity, @NonNull Request request);
    protected abstract void validationProcedureRequest(@NonNull Request request) throws InvalidInputDataException;
    protected abstract Optional<T> findEntity(@NonNull Request request);
}
