package org.university.payment_for_utilities.domains.abstract_class;

import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.MappedSuperclass;
import lombok.*;
import lombok.experimental.SuperBuilder;
import org.hibernate.annotations.DynamicInsert;
import org.hibernate.annotations.DynamicUpdate;
import org.university.payment_for_utilities.domains.receipt.Receipt;

@Getter
@Setter
@ToString
@SuperBuilder
@DynamicUpdate
@DynamicInsert
@MappedSuperclass
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(callSuper = false)
public abstract class ReceiptSearcher extends TableInfo {
    @ManyToOne
    @JoinColumn(name = "id_receipt", nullable = false, unique = true)
    @NonNull
    private Receipt receipt;

    @Override
    public boolean isEmpty() {
        return receipt.isEmpty();
    }

    protected static void initEmpty(@NonNull ReceiptSearcherBuilder<?, ?> builder) {
        TableInfo.initEmpty(builder);
        builder.receipt(Receipt.empty());
    }
}
