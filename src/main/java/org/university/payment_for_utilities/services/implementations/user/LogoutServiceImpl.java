package org.university.payment_for_utilities.services.implementations.user;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.university.payment_for_utilities.repositories.user.TokenRepository;
import org.university.payment_for_utilities.services.interfaces.user.LogoutService;

@Service
@RequiredArgsConstructor
public class LogoutServiceImpl implements LogoutService {
    private static final String HEADER = "Authorization";
    private static final String HEADER_START_FROM = "Bearer ";

    private final TokenRepository tokenRepository;

    @Override
    public void logout(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull Authentication authentication
    ) {
        final String authHeader = request.getHeader(HEADER);

        if(authHeader == null || !authHeader.startsWith(HEADER_START_FROM)) {
            return;
        }

        final String jwt = authHeader.substring(HEADER_START_FROM.length());
        var storedTokenOptional = tokenRepository
                .findByAccessToken(jwt);

        if(storedTokenOptional.isEmpty()) {
            return;
        }

        var storedToken = storedTokenOptional.get();
        storedToken.setExpired(true);
        storedToken.setRevoked(true);

        tokenRepository.save(storedToken);
        SecurityContextHolder.clearContext();
    }
}
