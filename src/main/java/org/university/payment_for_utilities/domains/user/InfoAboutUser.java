package org.university.payment_for_utilities.domains.user;

import jakarta.persistence.*;
import lombok.*;
import lombok.experimental.SuperBuilder;
import org.hibernate.annotations.DynamicInsert;
import org.hibernate.annotations.DynamicUpdate;
import org.jetbrains.annotations.Contract;
import org.university.payment_for_utilities.domains.abstract_class.TableInfo;

import static jakarta.persistence.CascadeType.*;

@Entity
@Getter
@Setter
@ToString
@SuperBuilder
@DynamicUpdate
@DynamicInsert
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(callSuper = false)
@Table(name = "info_about_users",
    uniqueConstraints = @UniqueConstraint(columnNames = {"first_name", "last_name"} )
)
public class InfoAboutUser extends TableInfo {
    @OneToOne(cascade={MERGE, REMOVE, REFRESH, DETACH})
    @JoinColumn(name = "id_registered_user", nullable = false, unique = true)
    @NonNull
    private RegisteredUser registered;

    @Column(name = "first_name", nullable = false)
    @NonNull
    private String firstName;

    @Column(name = "last_name", nullable = false)
    @NonNull
    private String lastName;

    @Override
    public boolean isEmpty() {
        return registered.isEmpty() ||
                firstName.isBlank() ||
                lastName.isBlank();
    }

    @Contract(" -> new")
    public static @NonNull InfoAboutUser empty() {
        var builder = builder();
        TableInfo.initEmpty(builder);

        return builder
                .registered(RegisteredUser.empty())
                .firstName("")
                .lastName("")
                .build();
    }
}
