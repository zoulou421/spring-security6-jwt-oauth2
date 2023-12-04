package com.formationkilo.security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private PasswordEncoder passwordEncoder;
    @Bean
    public InMemoryUserDetailsManager inMemoryUserDetailsManager(){
        return
                new InMemoryUserDetailsManager(
                    /*
                      User.withUsername("user1").password("{noop}1234").roles("USER").build(),
                      User.withUsername("user2").password("{noop}1234").roles("USER").build(),
                      User.withUsername("admin").password("{noop}1234").roles("USER","ADMIN").build()
                     */
                        /*
                        User.withUsername("user1").password(passwordEncoder.encode("1234")).roles("USER").build(),
                        User.withUsername("user2").password(passwordEncoder.encode("1234")).roles("USER").build(),
                        User.withUsername("admin").password(passwordEncoder.encode("1234")).roles("USER","ADMIN").build()
                                */
                        User.withUsername("user1").password(passwordEncoder.encode("1234")).authorities("USER").build(),
                        User.withUsername("user2").password(passwordEncoder.encode("1234")).authorities("USER").build(),
                        User.withUsername("admin").password(passwordEncoder.encode("1234")).authorities("USER","ADMIN").build()


                );

    }
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
       return   httpSecurity
                .csrf(csrf->csrf.disable())
                .authorizeHttpRequests((authorizeRequests) -> authorizeRequests
                       // .requestMatchers(AntPathRequestMatcher.antMatcher("/")).permitAll()
                        .anyRequest().authenticated()
                 )
                .httpBasic(Customizer.withDefaults())
                .sessionManagement((session) -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .build();
    }
}
