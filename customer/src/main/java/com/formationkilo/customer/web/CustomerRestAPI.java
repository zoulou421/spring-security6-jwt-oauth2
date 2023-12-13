package com.formationkilo.customer.web;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class CustomerRestAPI {
    @GetMapping("/customer")
    @PreAuthorize("hasAuthority('SCOPE_ROLE_ADMIN')")
    //@PreAuthorize("hasAuthority('ADMIN')")
    public Map<String,Object>customer(Authentication authentication){
        return Map.of("name","Bonevy",
                "email","bonevybeby@formationkilo.com",
                "username",authentication.getName(),
                "scope",authentication.getAuthorities()
        );
    }
}
