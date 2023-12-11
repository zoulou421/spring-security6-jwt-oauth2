package com.formationkilo.security.web;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class TestRestAPI {
   @GetMapping("/dataTest")
    public Map<String, Object>dataTest(){
        return Map.of("message","Data Test");
    }


    @GetMapping("/dataTest2")
    //@PreAuthorize("hasAuthority('SCOPE_USER')")
    public Map<String, Object>dataTest2(Authentication authentication){
        return Map.of(
                "message","Data Test",
                "username", authentication.getName(),
                "authorities",authentication.getAuthorities()

        );
    }

    @PostMapping("/saveData")
   // @PreAuthorize("hasAuthority('SCOPE_ADMIN')")
    @PreAuthorize("hasAuthority('SCOPE_ROLE_ADMIN')")
    public Map<String, Object>saveData(String data){
        return Map.of("dataSaved",data);
    }
}
