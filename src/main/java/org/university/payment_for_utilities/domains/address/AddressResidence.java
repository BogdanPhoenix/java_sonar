package org.university.payment_for_utilities.domains.address;

import jakarta.persistence.*;
import lombok.*;
import lombok.experimental.SuperBuilder;
import org.hibernate.annotations.DynamicInsert;
import org.hibernate.annotations.DynamicUpdate;
import org.jetbrains.annotations.Contract;
import org.springframework.data.redis.core.RedisHash;
import org.university.payment_for_utilities.domains.abstract_class.TableInfo;
import org.university.payment_for_utilities.domains.company.Company;
import org.university.payment_for_utilities.domains.user.RegisteredUser;

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
@EqualsAndHashCode(callSuper = false)
@Table(name = "addresses_residence",
    uniqueConstraints = {
            @UniqueConstraint(columnNames = {"id_settlement", "en_name_street", "num_house", "num_entrance"}),
            @UniqueConstraint(columnNames = {"id_settlement", "en_name_street", "num_house", "num_entrance", "num_apartment"})
    })
public class AddressResidence extends TableInfo {
    @ManyToOne
    @JoinColumn(name = "id_settlement", nullable = false)
    @NonNull
    private Settlement settlement;

    @Column(name = "ua_name_street", nullable = false)
    @NonNull
    private String uaNameStreet;

    @Column(name = "en_name_street", nullable = false)
    @NonNull
    private String enNameStreet;

    @Column(name = "num_house", length = 5, nullable = false)
    @NonNull
    private String numHouse;

    @Column(name = "num_entrance", length = 5)
    private String numEntrance;

    @Column(name = "num_apartment", length = 5)
    private String numApartment;

    @ToString.Exclude
    @EqualsAndHashCode.Exclude
    @OneToOne(mappedBy = "address", cascade = {MERGE, REMOVE, REFRESH, DETACH}, fetch = FetchType.LAZY)
    private Company company;

    @ToString.Exclude
    @EqualsAndHashCode.Exclude
    @ManyToMany(mappedBy = "addresses", cascade = {MERGE, REMOVE, REFRESH, DETACH}, fetch = FetchType.LAZY)
    private List<RegisteredUser> users;

    @Override
    public boolean isEmpty() {
        return settlement.isEmpty() ||
                uaNameStreet.isBlank() ||
                enNameStreet.isBlank() ||
                numHouse.isBlank();
    }

    @Contract(" -> new")
    public static @NonNull AddressResidence empty(){
        var builder = builder();
        TableInfo.initEmpty(builder);

        return builder
                .settlement(Settlement.empty())
                .uaNameStreet("")
                .enNameStreet("")
                .numHouse("")
                .numEntrance("")
                .numApartment("")
                .build();
    }
}
