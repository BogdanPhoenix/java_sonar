package org.university.payment_for_utilities.services.implementations.tools;

import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.Contract;
import org.university.payment_for_utilities.exceptions.NotFindEntityInDataBaseException;

import java.util.function.Function;

@Slf4j
public class ExceptionTools {
    private ExceptionTools() {}

    @Contract("_ -> new")
    public static @NonNull NotFindEntityInDataBaseException throwNotFindEntityInDataBaseException(@NonNull String message){
        log.error(message);
        return new NotFindEntityInDataBaseException(message);
    }

    public static void throwRuntimeException(@NonNull String message, @NonNull Function<String, ? extends RuntimeException> exception){
        log.error(message);
        throw exception.apply(message);
    }
}
