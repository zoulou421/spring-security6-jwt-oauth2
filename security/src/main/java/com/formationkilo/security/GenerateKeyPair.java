package com.formationkilo.security;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

public class GenerateKeyPair {
    public static void main(String[] args) throws NoSuchAlgorithmException, IOException {
        KeyPairGenerator keyPairGenerator=KeyPairGenerator.getInstance("RSA");
        var keyPair=keyPairGenerator.generateKeyPair();
        byte[] pub=keyPair.getPublic().getEncoded();
        byte[] pri=keyPair.getPrivate().getEncoded();

        PemWriter pemWriter1=new PemWriter(new OutputStreamWriter(new FileOutputStream("pub.pem")));
        PemObject pemObject1=new PemObject("PUBLIC KEY",pub);
        pemWriter1.writeObject(pemObject1);
        pemWriter1.close();

        PemWriter pemWriter2=new PemWriter(new OutputStreamWriter(new FileOutputStream("pri.pem")));
        PemObject pemObject2=new PemObject("PRIVATE KEY",pri);
        pemWriter2.writeObject(pemObject2);
        pemWriter2.close();

    }
}
