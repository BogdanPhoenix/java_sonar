package org.university.payment_for_utilities.enumarations;

import lombok.Getter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * An enumeration representing the different roles in the system.
 * Each constant represents a specific role that a user can have.
 */

@Getter
@RequiredArgsConstructor
public enum Role {
    EMPTY("", "", Set.of()),
    ADMIN("Адмін", "Admin", Set.of()),
    BANK_ADMIN("Адміністратор банку", "Bank administrator", Set.of()),
    COMPANY_ADMIN("Адміністратор компанії", "Company administrator", Set.of()),
    USER("Користувач", "User", Set.of());

    private final String uaName;
    private final String enName;
    private final Set<Permission> permissions;

    public @NonNull List<SimpleGrantedAuthority> getAuthorities() {
        var authorities = getPermissions()
                .stream()
                .map(permission -> new SimpleGrantedAuthority(permission.getValue()))
                .collect(Collectors.toList());
        authorities.add(new SimpleGrantedAuthority("ROLE_" + this.name()));
        return authorities;
    }
}
