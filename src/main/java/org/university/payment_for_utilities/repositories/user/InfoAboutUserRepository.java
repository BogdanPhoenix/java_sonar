package org.university.payment_for_utilities.repositories.user;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import org.university.payment_for_utilities.domains.user.InfoAboutUser;

import java.util.Optional;

@Repository
public interface InfoAboutUserRepository extends JpaRepository<InfoAboutUser, Long> {
    Optional<InfoAboutUser> findByFirstNameAndLastName(String firstName, String lastName);
}
