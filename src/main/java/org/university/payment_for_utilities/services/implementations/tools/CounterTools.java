package org.university.payment_for_utilities.services.implementations.tools;

import lombok.NonNull;
import org.university.payment_for_utilities.exceptions.InvalidInputDataException;
import org.university.payment_for_utilities.pojo.requests.abstract_class.CounterSearcherRequest;

import static org.university.payment_for_utilities.services.implementations.tools.ExceptionTools.throwRuntimeException;

public class CounterTools {
    private CounterTools() {}

    public static void validatePrevValueCounter(CounterSearcherRequest request) throws InvalidInputDataException {
        if(isPrevValueCounter(request)) {
            return;
        }

        var message = "The current meter reading you provide cannot be less than or equal to the previous one.";
        throwRuntimeException(message, InvalidInputDataException::new);
    }

    private static boolean isPrevValueCounter(@NonNull CounterSearcherRequest historyRequest) {
        return historyRequest.getPrevValueCounter() < historyRequest.getCurrentValueCounter();
    }
}
