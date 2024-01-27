package org.university.payment_for_utilities.domains.user;

import jakarta.persistence.*;
import lombok.*;
import lombok.experimental.SuperBuilder;
import org.hibernate.annotations.DynamicInsert;
import org.hibernate.annotations.DynamicUpdate;
import org.jetbrains.annotations.Contract;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.university.payment_for_utilities.domains.abstract_class.TableInfo;
import org.university.payment_for_utilities.domains.address.AddressResidence;
import org.university.payment_for_utilities.domains.bank.Bank;
import org.university.payment_for_utilities.domains.service_information_institutions.PhoneNum;
import org.university.payment_for_utilities.enumarations.Role;

import java.util.Collection;
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
@Table(name = "registered_users")
public class RegisteredUser extends TableInfo implements UserDetails {
    @Column(name = "user_email", nullable = false, unique = true)
    @NonNull
    private String username;

    @Column(name = "password_user", length = 1000, nullable = false)
    @NonNull
    private String password;

    @Enumerated(EnumType.STRING)
    private Role role;

    @OneToOne(cascade={MERGE, REMOVE, REFRESH, DETACH})
    @JoinColumn(name = "id_phone_num", nullable = false, unique = true)
    @NonNull
    private PhoneNum phoneNum;

    @ToString.Exclude
    @EqualsAndHashCode.Exclude
    @OneToOne(mappedBy = "registered", cascade = {MERGE, REMOVE, REFRESH, DETACH}, fetch = FetchType.LAZY)
    private InfoAboutUser infoUser;

    @ToString.Exclude
    @EqualsAndHashCode.Exclude
    @ManyToMany(cascade = {MERGE, REMOVE, REFRESH, DETACH}, fetch = FetchType.LAZY)
    @JoinTable(
            name = "user_payment_addresses",
            joinColumns = @JoinColumn(name = "id_registered_user", nullable = false),
            inverseJoinColumns = @JoinColumn(name = "id_address", nullable = false),
            uniqueConstraints = @UniqueConstraint(columnNames = {"id_registered_user", "id_address"})
    )
    private List<AddressResidence> addresses;

    @ToString.Exclude
    @EqualsAndHashCode.Exclude
    @ManyToMany(cascade = {MERGE, REMOVE, REFRESH, DETACH}, fetch = FetchType.LAZY)
    @JoinTable(
            name = "registered_user_banks",
            joinColumns = @JoinColumn(name = "id_registered_user", nullable = false),
            inverseJoinColumns = @JoinColumn(name = "id_bank", nullable = false),
            uniqueConstraints = @UniqueConstraint(columnNames = {"id_registered_user", "id_bank"})
    )
    private List<Bank> banks;

    @ToString.Exclude
    @EqualsAndHashCode.Exclude
    @OneToMany(mappedBy = "registeredUser", cascade = {MERGE, REMOVE, REFRESH, DETACH}, fetch = FetchType.LAZY)
    private List<ContractEntity> contractEntities;

    @ToString.Exclude
    @EqualsAndHashCode.Exclude
    @OneToMany(mappedBy = "user", cascade = {MERGE, REMOVE, REFRESH, DETACH}, fetch = FetchType.LAZY)
    private List<Token> tokens;

    @Override
    public boolean isEmpty() {
        return username.isBlank() ||
                password.isBlank() ||
                phoneNum.isEmpty() ||
                role == Role.EMPTY;
    }

    @Contract(" -> new")
    public static @NonNull RegisteredUser empty() {
        var builder = builder();
        TableInfo.initEmpty(builder);

        return builder
                .role(Role.EMPTY)
                .username("")
                .password("")
                .phoneNum(PhoneNum.empty())
                .build();
    }

    //Security

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return role.getAuthorities();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return currentData;
    }
}
