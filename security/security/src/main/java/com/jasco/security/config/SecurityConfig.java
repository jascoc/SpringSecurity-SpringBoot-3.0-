package com.jasco.security.config;

import jakarta.servlet.Filter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity // Security and Configuration annotation has to work together in spring boot 3
@RequiredArgsConstructor
// in this class we bind and manage the filters
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final AuthenticationProvider authenticationProvider;

    // let's bind the filters in this chain
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
        http
                .csrf()
                .disable()
                .authorizeHttpRequests() // we are disabling the security for some paths
                .requestMatchers("/api/v1/auth/**") // here we specify which path are in the whitelist
                .permitAll() // give all the access to those paths
                .anyRequest() // but any other request must be authenticated
                .authenticated()
                .and() // returns the same instance of HttpSecurity
                .sessionManagement() // here we specify how we want to create our session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS) // so it will be created a new session for each request
                .and()
                .authenticationProvider(authenticationProvider) // specify what is our authentication provider
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class); // to execute this filter before the default one (username and password filter)

        return http.build();
    }
}
