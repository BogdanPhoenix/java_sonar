package org.university.payment_for_utilities.pojo.requests.user;

import jakarta.persistence.MappedSuperclass;
import lombok.*;
import lombok.experimental.SuperBuilder;
import org.jetbrains.annotations.Contract;
import org.university.payment_for_utilities.domains.service_information_institutions.PhoneNum;
import org.university.payment_for_utilities.enumarations.Role;
import org.university.payment_for_utilities.pojo.requests.abstract_class.Request;

@Getter
@Setter
@ToString
@SuperBuilder
@MappedSuperclass
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(callSuper = false)
public class RegisteredUserRequest extends Request {
    private String username;
    private String password;
    private Role role;
    private PhoneNum phoneNum;

    @Override
    public boolean isEmpty() {
        return username.isBlank() ||
                password.isBlank() ||
                phoneNum.isEmpty() ||
                role == Role.EMPTY;
    }

    @Contract(" -> new")
    public static @NonNull RegisteredUserRequest empty() {
        return RegisteredUserRequest
                .builder()
                .username("")
                .password("")
                .role(Role.EMPTY)
                .phoneNum(PhoneNum.empty())
                .build();
    }
}
