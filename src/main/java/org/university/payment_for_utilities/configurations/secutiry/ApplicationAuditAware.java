package org.university.payment_for_utilities.configurations.secutiry;

import lombok.NonNull;
import org.springframework.data.domain.AuditorAware;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.university.payment_for_utilities.domains.user.RegisteredUser;

import java.util.Optional;

public class ApplicationAuditAware implements AuditorAware<Long> {
    @Override
    public @NonNull Optional<Long> getCurrentAuditor() {
        var authentication = SecurityContextHolder
                .getContext()
                .getAuthentication();

        if(isNotAuthenticated(authentication)) {
            return Optional.empty();
        }

        var registeredUser = (RegisteredUser) authentication.getPrincipal();

        return Optional.of(registeredUser.getId());
    }

    private boolean isNotAuthenticated(Authentication authentication) {
        return authentication == null
                || !authentication.isAuthenticated()
                || authentication instanceof AnonymousAuthenticationToken;
    }
}
