
package com.formationkilo.customer.config;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

//@Component
@ConfigurationProperties(prefix ="rsa")
//@ConfigurationProperties("rsa")
//@Getter
//@Setter
//@AllArgsConstructor
//@NoArgsConstructor
//public record RsaKeysConfig(@Value("${rsa.public-key}")RSAPublicKey publicKey) {
public class RsaKeysConfigCustomer {
    private RSAPublicKey publicKey;
    public RsaKeysConfigCustomer(RSAPublicKey publicKey) {
        this.publicKey = publicKey;
    }

    public RSAPublicKey getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(RSAPublicKey publicKey) {
        this.publicKey = publicKey;
    }
}