package com.jasco.security.config;

import com.jasco.security.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration // to let Spring recognize this class and at start up implements and injects all the Beans
@RequiredArgsConstructor // to maybe inject something
// holds all the application configuration such as Beans
public class ApplicationConfig {

    private final UserRepository userRepository;

    @Bean // constructor is a Bean
    public UserDetailsService userDetailsService() {
        // the userDetailsService has only 1 method (loadUserByUsername) so we can override it using lambda
        return username -> (
                userRepository.findByEmail(username)
                        .orElseThrow(() -> new UsernameNotFoundException(username + " not found"))
                );
    }

    @Bean // fetch and decode and encode passwords, this will be our Custom authentication provider
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setUserDetailsService(userDetailsService()); // giving the bean to set up the authentication provider
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder());
        return daoAuthenticationProvider;
    }

    @Bean // has the method that authenticates based on user and password
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean // encode password, you can choose one of your choice
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
