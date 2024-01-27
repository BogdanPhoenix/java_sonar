package org.university.payment_for_utilities;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@SpringBootApplication
@EnableJpaRepositories(basePackages = "org.university.payment_for_utilities.repositories")
public class PaymentForUtilitiesApplication {

	public static void main(String[] args) {
		SpringApplication.run(PaymentForUtilitiesApplication.class, args);
	}

}
