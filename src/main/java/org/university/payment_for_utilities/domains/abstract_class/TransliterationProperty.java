package org.university.payment_for_utilities.domains.abstract_class;

import jakarta.persistence.Column;
import jakarta.persistence.MappedSuperclass;
import lombok.*;
import lombok.experimental.SuperBuilder;
import org.hibernate.annotations.DynamicInsert;
import org.hibernate.annotations.DynamicUpdate;

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
public abstract class TransliterationProperty extends TableInfo {
    @Column(name = "ua_name", nullable = false, unique = true)
    @NonNull
    protected String uaName;

    @Column(name = "en_name", nullable = false, unique = true)
    @NonNull
    protected String enName;

    @Override
    public boolean isEmpty() {
        return uaName.isBlank() ||
                enName.isBlank();
    }

    protected static void initEmpty(@NonNull TransliterationPropertyBuilder<?, ?> builder){
        TableInfo.initEmpty(builder);
        builder
                .uaName("")
                .enName("");
    }
}
