package org.university.payment_for_utilities;

import lombok.NonNull;
import org.university.payment_for_utilities.pojo.requests.abstract_class.Request;
import org.university.payment_for_utilities.pojo.responses.abstract_class.Response;
import org.university.payment_for_utilities.services.implementations.CrudServiceAbstract;

import java.lang.reflect.InvocationTargetException;

public class AdditionalTestingTools {
    private AdditionalTestingTools(){}

    public static Object createEntity(@NonNull CrudServiceAbstract<?, ?> service, Request request){
        var response = service.addValue(request);

        var serviceAbstract = CrudServiceAbstract.class;
        try {
            var method = serviceAbstract.getDeclaredMethod("createEntity", Response.class);
            method.setAccessible(true);
            return method.invoke(service, response);
        } catch (NoSuchMethodException | InvocationTargetException | IllegalAccessException e) {
            throw new RuntimeException(e);
        }
    }
}
