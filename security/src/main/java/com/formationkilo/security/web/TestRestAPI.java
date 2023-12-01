package com.formationkilo.security.web;

import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class TestRestAPI {
    public Map<String, Object>dataTest(){
        return Map.of("message","Data test");
    }
}
