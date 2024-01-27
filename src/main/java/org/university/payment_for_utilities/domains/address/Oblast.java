package org.university.payment_for_utilities.domains.address;

import jakarta.persistence.*;
import lombok.*;
import lombok.experimental.SuperBuilder;
import org.hibernate.annotations.DynamicInsert;
import org.hibernate.annotations.DynamicUpdate;
import org.jetbrains.annotations.Contract;
import org.university.payment_for_utilities.domains.abstract_class.TransliterationProperty;

import java.util.List;

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
@EqualsAndHashCode(callSuper = true)
@Table(name = "oblasts")
public class Oblast extends TransliterationProperty {
    @ToString.Exclude
    @EqualsAndHashCode.Exclude
    @ManyToMany(cascade = {MERGE, REMOVE, REFRESH, DETACH}, fetch = FetchType.LAZY)
    @JoinTable(
            name = "oblast_districts",
            joinColumns = @JoinColumn(name = "id_oblast", nullable = false),
            inverseJoinColumns = @JoinColumn(name = "id_district", nullable = false),
            uniqueConstraints = @UniqueConstraint(columnNames = {"id_oblast", "id_district"})
    )
    private List<District> districts;

    @Contract(" -> new")
    public static @NonNull Oblast empty(){
        var builder = Oblast.builder();
        TransliterationProperty.initEmpty(builder);
        return builder.build();
    }
}
