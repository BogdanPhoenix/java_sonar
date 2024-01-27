package org.university.payment_for_utilities.controllers.service_information_institutions;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import org.university.payment_for_utilities.controllers.interfaces.CruController;
import org.university.payment_for_utilities.pojo.requests.service_information_institutions.PhoneNumRequest;
import org.university.payment_for_utilities.services.interfaces.service_information_institutions.PhoneNumService;

@RestController
@RequestMapping("/phone_numbers")
public class PhoneNumController extends CruController<PhoneNumRequest> {
    @Autowired
    public PhoneNumController(PhoneNumService service) {
        super(service);
    }
}
