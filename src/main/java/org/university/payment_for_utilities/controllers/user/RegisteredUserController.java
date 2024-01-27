package org.university.payment_for_utilities.controllers.user;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import org.university.payment_for_utilities.controllers.interfaces.CruController;
import org.university.payment_for_utilities.pojo.requests.user.RegisteredUserRequest;
import org.university.payment_for_utilities.pojo.responses.abstract_class.Response;
import org.university.payment_for_utilities.services.interfaces.user.RegisteredUserService;

@RestController
@RequestMapping("/users")
public class RegisteredUserController extends CruController<RegisteredUserRequest> {
    @Autowired
    public RegisteredUserController(RegisteredUserService service) {
        super(service);
    }

    @DeleteMapping("/{id}")
    public Response delete(@PathVariable Long id) {
        return service.removeValue(id);
    }
}
