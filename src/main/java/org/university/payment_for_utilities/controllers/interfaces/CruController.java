package org.university.payment_for_utilities.controllers.interfaces;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import org.university.payment_for_utilities.pojo.requests.abstract_class.Request;
import org.university.payment_for_utilities.pojo.requests.service_information_institutions.PhoneNumRequest;
import org.university.payment_for_utilities.pojo.responses.abstract_class.Response;
import org.university.payment_for_utilities.services.interfaces.CrudService;

import java.util.List;

public abstract class CruController<R extends Request> {
    protected final CrudService service;

    protected CruController(CrudService service) { this.service = service; }

    @GetMapping
    public List<Response> getAll() {
        return service.getAll();
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public Response create(@RequestBody R request){
        return service.addValue(request);
    }

    @GetMapping("/{id}")
    public Response getEntity(@PathVariable Long id) {
        return service.getById(id);
    }

    @PatchMapping("/{id}")
    public Response update(
            @PathVariable Long id,
            @RequestBody PhoneNumRequest request
    ){
        return service.updateValue(id, request);
    }
}
