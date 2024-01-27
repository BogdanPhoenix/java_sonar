package org.university.payment_for_utilities.services.implementations.service_information_institutions;

import lombok.NonNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.university.payment_for_utilities.domains.service_information_institutions.UnitMeasurement;
import org.university.payment_for_utilities.pojo.requests.abstract_class.Request;
import org.university.payment_for_utilities.pojo.responses.abstract_class.Response;
import org.university.payment_for_utilities.pojo.responses.service_information_institutions.UnitMeasurementResponse;
import org.university.payment_for_utilities.repositories.service_information_institutions.UnitMeasurementRepository;
import org.university.payment_for_utilities.services.implementations.auxiliary_services.TransliterationService;
import org.university.payment_for_utilities.services.interfaces.company.TypeOfferService;
import org.university.payment_for_utilities.services.interfaces.service_information_institutions.UnitMeasurementService;

@Service
public class UnitMeasurementServiceImpl extends TransliterationService<UnitMeasurement, UnitMeasurementRepository> implements UnitMeasurementService {
    private final TypeOfferService typeOfferService;

    @Autowired
    public UnitMeasurementServiceImpl(
            UnitMeasurementRepository repository,
            TypeOfferService typeOfferService
    ) {
        super(repository, "Units measurement");
        this.typeOfferService = typeOfferService;
    }

    @Override
    protected UnitMeasurement createEntity(Request request) {
        var builder = UnitMeasurement.builder();
        super.initTransliterationPropertyBuilder(builder, request);
        return builder.build();
    }

    @Override
    protected UnitMeasurement createEntity(Response response) {
        var builder = UnitMeasurement.builder();
        super.initTransliterationPropertyBuilder(builder, response);
        return builder.build();
    }

    @Override
    protected Response createResponse(@NonNull UnitMeasurement entity) {
        var builder = UnitMeasurementResponse.builder();
        super.initResponseBuilder(builder, entity);
        return builder.build();
    }

    @Override
    protected void deactivatedChildren(@NonNull UnitMeasurement entity) {
        deactivateChildrenCollection(entity.getOffers(), typeOfferService);
    }
}
