package com.encrypt;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Hello world!
 *
 */
public class App {
    public static void main(String[] args) throws Exception{
        String message = "Now let's implement SHA and RSA together!";

        byte[] hashText = Sha256.hash(message);
        String hashedText = new String(hashText);

        KeyPair keyPair = Rsa.generateRsaKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        byte[] encryptedText = Rsa.encrypt(hashedText, publicKey);
        String decryptedText = Rsa.decrypt(encryptedText, privateKey);

        System.out.println("Message : " + message);
        System.out.println("Hashed Message with SHA-256 : " + hashedText);
        System.out.println("Encrypted Message SHA-256 with RSA : " + new String(encryptedText));
        System.out.println("Decrypted Message SHA-256 with RSA : " + decryptedText);
        System.out.println("Check equals message : " + hashedText.equals(decryptedText));
    }
}
