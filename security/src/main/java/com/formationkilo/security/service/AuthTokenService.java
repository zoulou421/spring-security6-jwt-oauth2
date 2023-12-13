package com.formationkilo.security.service;

import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class AuthTokenService {

    public Map<String,String> authenticate(String grantType,
                                           String username,
                                           String password,
                                           boolean withRefreshToken,
                                           String refreshToken){
        //Build this class to centralise the token code you have in the AuthController
        //REFACTORY OF YOUR CODE

      return null;
    }
}
