package org.university.payment_for_utilities.services.implementations.service_information_institutions;

import lombok.NonNull;
import org.springframework.stereotype.Service;
import org.university.payment_for_utilities.domains.service_information_institutions.Website;
import org.university.payment_for_utilities.exceptions.InvalidInputDataException;
import org.university.payment_for_utilities.pojo.requests.abstract_class.Request;
import org.university.payment_for_utilities.pojo.requests.service_information_institutions.WebsiteRequest;
import org.university.payment_for_utilities.pojo.responses.abstract_class.Response;
import org.university.payment_for_utilities.pojo.responses.service_information_institutions.WebsiteResponse;
import org.university.payment_for_utilities.repositories.service_information_institutions.WebsiteRepository;
import org.university.payment_for_utilities.services.implementations.CrudServiceAbstract;
import org.university.payment_for_utilities.services.interfaces.service_information_institutions.WebsiteService;

import java.util.Optional;

import static org.university.payment_for_utilities.services.implementations.tools.ExceptionTools.throwRuntimeException;

@Service
public class WebsiteServiceImpl extends CrudServiceAbstract<Website, WebsiteRepository> implements WebsiteService {
    private static final String WEBSITE_TEMPLATE = "^(http|https)://.+";

    protected WebsiteServiceImpl(WebsiteRepository repository) {
        super(repository, "Websites");
    }

    @Override
    protected Website createEntity(Request request) {
        var websiteRequest = (WebsiteRequest) request;
        return Website
                .builder()
                .value(websiteRequest.getValue())
                .build();
    }

    @Override
    protected Website createEntity(Response response) {
        var websiteResponse = (WebsiteResponse) response;
        var builder = Website.builder();
        initEntityBuilder(builder, response);

        return builder
                .value(websiteResponse.getValue())
                .build();
    }

    @Override
    protected Response createResponse(@NonNull Website entity) {
        var builder = WebsiteResponse.builder();
        initResponseBuilder(builder, entity);

        return builder
                .value(entity.getValue())
                .build();
    }

    @Override
    protected void updateEntity(@NonNull Website entity, @NonNull Request request) {
        var newValue = (WebsiteRequest) request;

        if(!newValue.getValue().isBlank()){
            entity.setValue(newValue.getValue());
        }
    }

    @Override
    protected void validationProcedureRequest(@NonNull Request request) throws InvalidInputDataException {
        var websiteRequest = (WebsiteRequest) request;
        validateWebSite(websiteRequest.getValue());
    }

    private void validateWebSite(@NonNull String webSite) throws InvalidInputDataException {
        if (isWebSite(webSite)){
            return;
        }

        var message = String.format("The link you provided: \"%s\" to the bank's website was not validated. It must match the following template: \"%s\".", webSite, WEBSITE_TEMPLATE);
        throwRuntimeException(message, InvalidInputDataException::new);
    }

    private boolean isWebSite(@NonNull String webSite){
        return webSite.isEmpty() ||
                webSite.toLowerCase()
                        .matches(WEBSITE_TEMPLATE);
    }

    @Override
    protected Optional<Website> findEntity(@NonNull Request request) {
        var websiteRequest = (WebsiteRequest) request;
        return repository
                .findByValue(
                        websiteRequest.getValue()
                );
    }
}
