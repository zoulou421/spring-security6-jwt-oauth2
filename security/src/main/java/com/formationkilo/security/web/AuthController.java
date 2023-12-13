
package com.formationkilo.security.web;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;


@RestController
@RequiredArgsConstructor
public class AuthController {

   private final JwtEncoder jwtEncoder;
   //update:
   private final JwtDecoder jwtDecoder;
   private final UserDetailsService userDetailsService;
   //add this:
   private final AuthenticationManager authenticationManagerBean;
   @PostMapping("/token2")
   public Map<String,String>jwtToken2(Authentication authentication){
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
   @PostMapping("/token3")
   public Map<String,String>jwtToken3(String username, String password){
      Authentication authentication=authenticationManagerBean.authenticate(
              new UsernamePasswordAuthenticationToken(username,password)
      );
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
   @PostMapping("/token4")
   public Map<String,String>jwtToken4(String username, String password, boolean withRefreshToken){
      Authentication authentication=authenticationManagerBean.authenticate(
              new UsernamePasswordAuthenticationToken(username,password)
      );
      Map<String,String>idToken=new HashMap<>();
      Instant instant=Instant.now();
      //Collection<? extends GrantedAuthority>authorities=authentication.getAuthorities()
      String scope=authentication.getAuthorities().stream().map(aut->aut.getAuthority())
              .collect(Collectors.joining(" "));
      JwtClaimsSet jwtClaimsSet=JwtClaimsSet.builder()
              .subject(authentication.getName())
              .issuedAt(instant)//actuel date or system date
              .expiresAt(instant.plus(withRefreshToken?1:5, ChronoUnit.MINUTES))
              .issuer("security")// security represent the app name that generated the token
              .claim("scope",scope)
              .build();
      String jwtAcessToken=jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSet)).getTokenValue();
      idToken.put("accessToken",jwtAcessToken);
      if(withRefreshToken){
         JwtClaimsSet jwtClaimsSetRefresh=JwtClaimsSet.builder()
                 .subject(authentication.getName())
                 .issuedAt(instant)//actuel date or system date
                 .expiresAt(instant.plus(5, ChronoUnit.MINUTES))
                 .issuer("security")// security represent the app name that generated the token
                 //.claim("scope",scope) you don't need to send roles.
                 .build();
         String jwtRefreshToken=jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSetRefresh)).getTokenValue();
         //add this:
         idToken.put("RefreshToken",jwtRefreshToken);

      }
      return idToken;
   }

   //update: String grantType,refreshToken ADDED
   @PostMapping("/token5")
   public Map<String,String>jwtToken5(String grantType,
                                     String username,
                                     String password,
                                     boolean withRefreshToken,
                                     String refreshToken){
       String  subject=null;String scope=null;
      //Authentication authentication=null;
      if(grantType!="" && grantType.equals("password")){
         Authentication authentication=authenticationManagerBean.authenticate(
                new UsernamePasswordAuthenticationToken(username,password)
        );
         subject=authentication.getName();
         scope=authentication.getAuthorities().stream().map(aut->aut.getAuthority())
                 .collect(Collectors.joining(" "));
     }else if(grantType!="" && grantType.equals("refreshToken")){
         Jwt decodeJWT= jwtDecoder.decode(refreshToken);
         subject=decodeJWT.getSubject();
         UserDetails userDetails=userDetailsService.loadUserByUsername(subject);
         Collection<? extends GrantedAuthority> authorities=userDetails.getAuthorities();
         scope=authorities.stream().map(aut->aut.getAuthority()).collect(Collectors.joining(" "));
      }
      Map<String,String>idToken=new HashMap<>();
      Instant instant=Instant.now();
      //Collection<? extends GrantedAuthority>authorities=authentication.getAuthorities()
     // String scope=authentication.getAuthorities().stream().map(aut->aut.getAuthority())
      //        .collect(Collectors.joining(" "));
      JwtClaimsSet jwtClaimsSet=JwtClaimsSet.builder()
              .subject(subject)
              .issuedAt(instant)//actuel date or system date
              .expiresAt(instant.plus(withRefreshToken?1:5, ChronoUnit.MINUTES))
              .issuer("security")// security represent the app name that generated the token
              .claim("scope",scope)
              .build();
      String jwtAcessToken=jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSet)).getTokenValue();
      idToken.put("accessToken",jwtAcessToken);
      if(withRefreshToken){
         JwtClaimsSet jwtClaimsSetRefresh=JwtClaimsSet.builder()
                 .subject(subject)
                 .issuedAt(instant)//actuel date or system date
                 .expiresAt(instant.plus(5, ChronoUnit.MINUTES))
                 .issuer("security")// security represent the app name that generated the token
                 //.claim("scope",scope) you don't need to send roles.
                 .build();
         String jwtRefreshToken=jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSetRefresh)).getTokenValue();
         //add this:
         idToken.put("refreshToken",jwtRefreshToken);

      }
      return idToken;
   }
    //update: String grantType,refreshToken ADDED
    @PostMapping("/token")
    public ResponseEntity<Map<String,String>> jwtToken(String grantType,
                                                       String username,
                                                       String password,
                                                       boolean withRefreshToken,
                                                       String refreshToken){
        String  subject=null;String scope=null;
        //Authentication authentication=null;
        if(grantType!="" && grantType.equals("password")){
            Authentication authentication=authenticationManagerBean.authenticate(
                    new UsernamePasswordAuthenticationToken(username,password)
            );
            subject=authentication.getName();
            scope=authentication.getAuthorities().stream().map(aut->aut.getAuthority())
                    .collect(Collectors.joining(" "));
        }else if(grantType!="" && grantType.equals("refreshToken")){
            //added part
            if(refreshToken==null){
               return new ResponseEntity<>(Map.of("errorMessage","refreshToken is required"), HttpStatus.UNAUTHORIZED);
            }
            Jwt decodeJWT= null;
            try {
                decodeJWT = jwtDecoder.decode(refreshToken);
            } catch (JwtException e) {
                return new ResponseEntity<>(Map.of("errorMessage",e.getMessage()), HttpStatus.UNAUTHORIZED);
               // throw new RuntimeException(e);
            }
            subject=decodeJWT.getSubject();
            UserDetails userDetails=userDetailsService.loadUserByUsername(subject);
            Collection<? extends GrantedAuthority> authorities=userDetails.getAuthorities();
            scope=authorities.stream().map(aut->aut.getAuthority()).collect(Collectors.joining(" "));
        }
        Map<String,String>idToken=new HashMap<>();
        Instant instant=Instant.now();
        //Collection<? extends GrantedAuthority>authorities=authentication.getAuthorities()
        // String scope=authentication.getAuthorities().stream().map(aut->aut.getAuthority())
        //        .collect(Collectors.joining(" "));
        JwtClaimsSet jwtClaimsSet=JwtClaimsSet.builder()
                .subject(subject)
                .issuedAt(instant)//actuel date or system date
                .expiresAt(instant.plus(withRefreshToken?1:5, ChronoUnit.MINUTES))
                .issuer("security")// security represent the app name that generated the token
                .claim("scope",scope)
                .build();
        String jwtAcessToken=jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSet)).getTokenValue();
        idToken.put("accessToken",jwtAcessToken);
        if(withRefreshToken){
            JwtClaimsSet jwtClaimsSetRefresh=JwtClaimsSet.builder()
                    .subject(subject)
                    .issuedAt(instant)//actuel date or system date
                    .expiresAt(instant.plus(5, ChronoUnit.MINUTES))
                    .issuer("security")// security represent the app name that generated the token
                    //.claim("scope",scope) you don't need to send roles.
                    .build();
            String jwtRefreshToken=jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSetRefresh)).getTokenValue();
            //add this:
            idToken.put("refreshToken",jwtRefreshToken);

        }
        return new ResponseEntity<>(idToken,HttpStatus.OK);
    }
}