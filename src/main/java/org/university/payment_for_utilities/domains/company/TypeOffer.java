package org.university.payment_for_utilities.domains.company;

import jakarta.persistence.*;
import lombok.*;
import lombok.experimental.SuperBuilder;
import org.hibernate.annotations.DynamicInsert;
import org.hibernate.annotations.DynamicUpdate;
import org.jetbrains.annotations.Contract;
import org.university.payment_for_utilities.domains.abstract_class.TransliterationProperty;
import org.university.payment_for_utilities.domains.service_information_institutions.UnitMeasurement;

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
@Table(name = "types_offers",
        uniqueConstraints = {
            @UniqueConstraint(columnNames = {"id_unit", "en_name"})
    }
)
public class TypeOffer extends TransliterationProperty {
    @ManyToOne
    @JoinColumn(name = "id_unit", nullable = false)
    @NonNull
    private UnitMeasurement unitMeasurement;

    @ToString.Exclude
    @EqualsAndHashCode.Exclude
    @OneToMany(mappedBy = "type", cascade={MERGE, REMOVE, REFRESH, DETACH}, fetch = FetchType.LAZY)
    private List<CompanyTariff> tariffs;

    @Override
    public boolean isEmpty() {
        return super.isEmpty() ||
                unitMeasurement.isEmpty();
    }

    @Contract(" -> new")
    public static @NonNull TypeOffer empty(){
        var builder = TypeOffer.builder();
        TransliterationProperty.initEmpty(builder);

        return builder
                .unitMeasurement(UnitMeasurement.empty())
                .build();
    }
}
