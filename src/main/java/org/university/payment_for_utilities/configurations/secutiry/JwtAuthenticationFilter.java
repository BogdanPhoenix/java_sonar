package org.university.payment_for_utilities.configurations.secutiry;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.university.payment_for_utilities.repositories.user.TokenRepository;
import org.university.payment_for_utilities.services.interfaces.JwtService;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private static final String HEADER = "Authorization";
    private static final String HEADER_START_FROM = "Bearer ";
    private static final String URI = "/";

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;
    private final TokenRepository tokenRepository;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        var servletPath = request.getServletPath();

        if(servletPath.contains(URI) || !hasValidHeader(request)){
            filterChain.doFilter(request, response);
            return;
        }

        var jwt = extractJwtFromHeader(request);
        var username = jwtService.extractUsername(jwt);

        if(username != null && SecurityContextHolder.getContext().getAuthentication() == null){
            authorizeRequest(request, jwt, username);
        }

        filterChain.doFilter(request, response);
    }

    private boolean hasValidHeader(@NonNull HttpServletRequest request){
        String authHeader = request.getHeader(HEADER);
        return authHeader != null && authHeader.startsWith(HEADER_START_FROM);
    }

    private @NonNull String extractJwtFromHeader(@NonNull HttpServletRequest request){
        var authHeader = request.getHeader(HEADER);
        return authHeader.substring(HEADER_START_FROM.length());
    }

    private void authorizeRequest(HttpServletRequest request, String jwt, String userEmail){
        var userDetails = this.userDetailsService.loadUserByUsername(userEmail);

        var isTokenValid = tokenRepository.findByAccessToken(jwt)
                .map(token -> !token.isExpired() && !token.isRevoked())
                .orElse(false);

        if(!(jwtService.isTokenValid(jwt, userDetails) && Boolean.TRUE.equals(isTokenValid))){
            return;
        }

        var authToken = new UsernamePasswordAuthenticationToken(
                userDetails, null, userDetails.getAuthorities()
        );

        authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(authToken);
    }
}
