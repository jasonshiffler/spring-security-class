package com.shiffler.springsecurityclass.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import static com.shiffler.springsecurityclass.security.ApplicationUserRole.*;
import static org.springframework.security.core.userdetails.User.*;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                //.csrf().disable()//This is ok if we're just doing a REST API
                .authorizeRequests()
                .anyRequest()
                .authenticated()
                .and()
                .httpBasic(); //httpBasic requires authentication everytime a resource is accessed
    }

    @Override
    @Bean
    protected UserDetailsService userDetailsService() {

        UserDetails userDetails1 = builder()
                .username("jamesbond")
                .password(passwordEncoder.encode("password"))
                //.roles(ApplicationUserRole.STUDENT.name())
                .authorities(STUDENT.getGrantedAuthorities())
                .build();

        UserDetails userDetails2 = builder()
                .username("jackishiffler")
                .password(passwordEncoder.encode("password"))
                //.roles(ApplicationUserRole.ADMIN.name())
                .authorities(ADMIN.getGrantedAuthorities())
                .build();

        UserDetails userDetails3 = builder()
                .username("jasonshiffler")
                .password(passwordEncoder.encode("password"))
                //.roles(ApplicationUserRole.ADMINTRAINEE.name())
                .authorities(ADMINTRAINEE.getGrantedAuthorities())
                .build();

        return new InMemoryUserDetailsManager(userDetails1, userDetails2,userDetails3);

    }
}
