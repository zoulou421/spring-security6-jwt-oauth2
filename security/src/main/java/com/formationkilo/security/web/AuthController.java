
package com.formationkilo.security.web;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;


@RestController
@RequiredArgsConstructor
public class AuthController {

   private final JwtEncoder jwtEncoder;
   @PostMapping("/token")
   public Map<String,String>jwtToken(Authentication authentication){
      Map<String,String>idToken=new HashMap<>();
      Instant instant=Instant.now();
      //Collection<? extends GrantedAuthority>authorities=authentication.getAuthorities()
      String scope=authentication.getAuthorities().stream().map(aut->aut.getAuthority())
              .collect(Collectors.joining(" "));
      JwtClaimsSet jwtClaimsSet=JwtClaimsSet.builder()
              .subject(authentication.getName())
              .issuedAt(instant)//actuel date or system date
              .expiresAt(instant.plus(5, ChronoUnit.MINUTES))
              .issuer("security")// security represent the app name that generated the token
              .claim("scope",scope)

              .build();
      String jwtAcessToken=jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSet)).getTokenValue();
      idToken.put("accessToken",jwtAcessToken);
      return idToken;
   }
}