package org.university.payment_for_utilities.services.implementations.company;

import lombok.NonNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.university.payment_for_utilities.domains.company.TypeOffer;
import org.university.payment_for_utilities.pojo.requests.company.TypeOfferRequest;
import org.university.payment_for_utilities.pojo.requests.abstract_class.Request;
import org.university.payment_for_utilities.pojo.responses.company.TypeOfferResponse;
import org.university.payment_for_utilities.pojo.responses.abstract_class.Response;
import org.university.payment_for_utilities.repositories.company.TypeOfferRepository;
import org.university.payment_for_utilities.services.implementations.auxiliary_services.TransliterationService;
import org.university.payment_for_utilities.services.interfaces.company.CompanyTariffService;
import org.university.payment_for_utilities.services.interfaces.company.TypeOfferService;

import java.util.Optional;

@Service
public class TypeOfferServiceImpl extends TransliterationService<TypeOffer, TypeOfferRepository> implements TypeOfferService {
    private final CompanyTariffService companyTariffService;

    @Autowired
    public TypeOfferServiceImpl(
            TypeOfferRepository repository,
            CompanyTariffService companyTariffService
    ) {
        super(repository, "Type offers");
        this.companyTariffService = companyTariffService;
    }

    @Override
    protected TypeOffer createEntity(Request request) {
        var builder = TypeOffer.builder();
        super.initTransliterationPropertyBuilder(builder, request);
        var typeOfferRequest = (TypeOfferRequest) request;

        return builder
                .unitMeasurement(typeOfferRequest.getUnitMeasurement())
                .build();
    }

    @Override
    protected TypeOffer createEntity(Response response) {
        var builder = TypeOffer.builder();
        super.initTransliterationPropertyBuilder(builder, response);
        var typeOfferResponse = (TypeOfferResponse) response;

        return builder
                .unitMeasurement(typeOfferResponse.getUnitMeasurement())
                .build();
    }

    @Override
    protected Response createResponse(@NonNull TypeOffer entity) {
        var builder = TypeOfferResponse.builder();
        super.initResponseBuilder(builder, entity);
        return builder
                .unitMeasurement(entity.getUnitMeasurement())
                .build();
    }

    @Override
    protected void deactivatedChildren(@NonNull TypeOffer entity) {
        deactivateChildrenCollection(entity.getTariffs(), companyTariffService);
    }

    @Override
    protected Optional<TypeOffer> findEntity(@NonNull Request request) {
        var typeOfferRequest = (TypeOfferRequest) request;
        return repository
                .findByUnitMeasurementAndEnName(
                        typeOfferRequest.getUnitMeasurement(),
                        typeOfferRequest.getEnName()
                );
    }
}
