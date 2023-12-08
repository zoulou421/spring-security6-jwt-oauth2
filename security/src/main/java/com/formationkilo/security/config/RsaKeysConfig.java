
package com.formationkilo.security.config;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.sql.Array;

import lombok.*;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

//@Component
@ConfigurationProperties(prefix ="rsa")
//@ConfigurationProperties("rsa")
@Getter
@Setter
@AllArgsConstructor
//@NoArgsConstructor
//public record RsaKeysConfig(@Value("${rsa.public-key}")RSAPublicKey publicKey, @Value("${rsa.private-key}")RSAPrivateKey privateKey) {
public class RsaKeysConfig {
    private RSAPublicKey publicKey;
    private RSAPrivateKey privateKey;
}