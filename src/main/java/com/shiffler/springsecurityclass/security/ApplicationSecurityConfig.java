package com.shiffler.springsecurityclass.security;

import com.shiffler.springsecurityclass.auth.ApplicationUserDao;
import com.shiffler.springsecurityclass.auth.ApplicationUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
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
    private final ApplicationUserService applicationUserService;

    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder, ApplicationUserService applicationUserService)
    {
        this.passwordEncoder = passwordEncoder;
        this.applicationUserService = applicationUserService;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()//This is ok if we're just doing a REST API
                .authorizeRequests()
                .antMatchers("/api/**").hasRole(STUDENT.name())
                .antMatchers("/","index","/css/*","/js/*").permitAll()
                .anyRequest()
                .authenticated()
                .and()
                //.httpBasic(); //httpBasic requires authentication everytime a resource is accessed
                .formLogin() //enable form based authentication, leverages SESSIONID cookie after first auth
                             //by default sessionid is stored in memory
                .loginPage("/login") //defines the login page
                .permitAll() //makes sure the login page is accessible.
                .defaultSuccessUrl("/courses",true);
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception{
        auth.authenticationProvider(daoAuthenticationProvider());
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider(){
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder);
        provider.setUserDetailsService(applicationUserService);
        return provider;
    }

/*
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

 */
}
