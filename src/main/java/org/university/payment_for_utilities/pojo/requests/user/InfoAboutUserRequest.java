package org.university.payment_for_utilities.pojo.requests.user;

import jakarta.persistence.MappedSuperclass;
import lombok.*;
import lombok.experimental.SuperBuilder;
import org.jetbrains.annotations.Contract;
import org.university.payment_for_utilities.domains.user.RegisteredUser;
import org.university.payment_for_utilities.pojo.requests.abstract_class.Request;

@Getter
@Setter
@ToString
@SuperBuilder
@MappedSuperclass
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(callSuper = false)
public class InfoAboutUserRequest extends Request {
    private RegisteredUser registered;
    private String firstName;
    private String lastName;

    @Override
    public boolean isEmpty() {
        return registered.isEmpty() ||
                firstName.isBlank() ||
                lastName.isBlank();
    }

    @Contract(" -> new")
    public static @NonNull InfoAboutUserRequest empty() {
        return InfoAboutUserRequest
                .builder()
                .registered(RegisteredUser.empty())
                .firstName("")
                .lastName("")
                .build();
    }
}
