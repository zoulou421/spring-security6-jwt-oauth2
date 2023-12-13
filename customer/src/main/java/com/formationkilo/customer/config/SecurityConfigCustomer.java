package com.formationkilo.customer.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfigCustomer {
    private final RsaKeysConfigCustomer rsaKeysConfigCustomer;

    public SecurityConfigCustomer(RsaKeysConfigCustomer rsaKeysConfigCustomer) {
        this.rsaKeysConfigCustomer = rsaKeysConfigCustomer;
    }

    @Bean
    public SecurityFilterChain securityFilterChainCustomer(HttpSecurity http) throws Exception {
        http
                .csrf(csrf->csrf.disable())
                .authorizeHttpRequests((authorizeRequests) -> authorizeRequests
                       .anyRequest().authenticated())
               .oauth2ResourceServer((oauth2) -> oauth2.jwt(Customizer.withDefaults()));
        return http.build();
    }
    @Bean
    public JwtDecoder jwtDecoder(){
        return NimbusJwtDecoder.withPublicKey(rsaKeysConfigCustomer.getPublicKey()).build();
    }

}
