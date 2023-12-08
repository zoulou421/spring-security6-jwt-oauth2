package com.formationkilo.security.config;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWT;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;


@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    private final RsaKeysConfig rsaKeysConfig;
    private final PasswordEncoder passwordEncoder;
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
                        User.withUsername("user1").password("{noop}1234").authorities("USER").build(),
                        User.withUsername("user2").password("{noop}1234").authorities("USER").build(),
                        User.withUsername("admin").password("{noop}1234").authorities("USER","ADMIN").build()
                        */


                        User.withUsername("user1").password(passwordEncoder.encode("1234")).roles("USER").build(),
                        User.withUsername("user2").password(passwordEncoder.encode("1234")).roles("USER").build(),
                        User.withUsername("admin").password(passwordEncoder.encode("1234")).roles("USER","ADMIN").build()

                        /*
                         */
                        /*
                        User.withUsername("user1").password(passwordEncoder.encode("1234")).authorities("USER").build(),
                        User.withUsername("user2").password(passwordEncoder.encode("1234")).authorities("USER").build(),
                        User.withUsername("admin").password(passwordEncoder.encode("1234")).authorities("USER","ADMIN").build()
                                */
                );
    }
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http ) throws Exception {
          http
                .csrf(csrf->csrf.disable())
                .authorizeHttpRequests((authorizeRequests) -> authorizeRequests
                         .requestMatchers(AntPathRequestMatcher.antMatcher("/dataTest")).permitAll()
                        .anyRequest().authenticated()
                )
                .httpBasic(Customizer.withDefaults())
                .sessionManagement((session) -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                  .oauth2ResourceServer((oauth2) -> oauth2.jwt(Customizer.withDefaults()))
          ;
        return http.build();
    }

    @Bean
    public JwtDecoder jwtDecoder(){
        return NimbusJwtDecoder.withPublicKey(rsaKeysConfig.getPublicKey()).build();
    }
     @Bean
    public JwtEncoder jwtEncoder(){
         JWK jwk=new RSAKey.Builder(rsaKeysConfig.getPublicKey()).privateKey(rsaKeysConfig.getPrivateKey()).build();
         JWKSource<SecurityContext>jwkSource=new ImmutableJWKSet<>(new JWKSet(jwk));
         return new NimbusJwtEncoder(jwkSource);

    }



}