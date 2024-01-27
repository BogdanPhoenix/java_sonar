package org.university.payment_for_utilities.services.implementations.address;

import lombok.NonNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.university.payment_for_utilities.domains.address.Oblast;
import org.university.payment_for_utilities.pojo.requests.abstract_class.Request;
import org.university.payment_for_utilities.pojo.responses.abstract_class.Response;
import org.university.payment_for_utilities.repositories.address.OblastRepository;
import org.university.payment_for_utilities.services.implementations.auxiliary_services.TransliterationService;
import org.university.payment_for_utilities.services.interfaces.address.OblastService;
import org.university.payment_for_utilities.pojo.responses.address.OblastResponse;

@Service
public class OblastServiceImpl extends TransliterationService<Oblast, OblastRepository> implements OblastService {
    @Autowired
    public OblastServiceImpl(OblastRepository repository){
        super(repository, "Oblasts");
    }

    @Override
    protected Oblast createEntity(@NonNull Request request){
        var builder = Oblast.builder();
        super.initTransliterationPropertyBuilder(builder, request);
        return builder.build();
    }

    @Override
    protected Oblast createEntity(Response response) {
        var builder = Oblast.builder();
        super.initTransliterationPropertyBuilder(builder, response);
        return builder.build();
    }

    @Override
    protected Response createResponse(@NonNull Oblast entity){
        var builder = OblastResponse.builder();
        super.initResponseBuilder(builder, entity);
        return builder.build();
    }
}
