package org.university.payment_for_utilities.domains.receipt;

import jakarta.persistence.*;
import lombok.*;
import lombok.experimental.SuperBuilder;
import org.hibernate.annotations.DynamicInsert;
import org.hibernate.annotations.DynamicUpdate;
import org.jetbrains.annotations.Contract;
import org.university.payment_for_utilities.domains.abstract_class.CounterSearcher;

@Entity
@Getter
@Setter
@ToString
@SuperBuilder
@DynamicUpdate
@DynamicInsert
@NoArgsConstructor
@EqualsAndHashCode(callSuper = true)
@Table(name = "blocks_meter_readings")
public class BlockMeterReading extends CounterSearcher {
    @Contract(" -> new")
    public static @NonNull BlockMeterReading empty() {
        var builder = builder();
        CounterSearcher.initEmpty(builder);
        return builder.build();
    }
}
