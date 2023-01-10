package com.jasco.security.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor // will create a constructor with any private final field
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    // this instance will manage the jwt and do all the management stuff so all the method to work with jwt
    private final JwtService jwtService;
    private final UserDetailsService userDetailsService; // the service Bean to access and perform queries on User table

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        // extracting the header from the request, in the header called Authorization is stored Jwt Token
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String userEmail;

        // if the header is null or the header does not start with "Bearer " something went wrong, we do an early return
        if(authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        // we do a sub 7 to subtract "Bearer "
        jwt = authHeader.substring(7);
        userEmail = jwtService.extractUsername(jwt);
                                // checking if the user is already authenticated, if yes we don't have to perform all the checks
        if(userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            // we check if the user is in the database, so we retrieve it
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);

            // check if the token is valid let's update the security context
            if(jwtService.isTokenValid(jwt, userDetails)) {
                // this token is needed to Spring to update the security context
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null, // we don't have the credential yet
                        userDetails.getAuthorities()
                );
                // giving more detail to the authToken
                authToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );
                // now finally update the security context
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        // passing the job to the next filter
        filterChain.doFilter(request, response);
    }
}
