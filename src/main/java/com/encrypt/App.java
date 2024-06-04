package com.encrypt;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class App {
    public static void main(String[] args) throws Exception {
        String message = "Now let's implement SHA and RSA together!";
        System.out.println("Message : " + message);

        byte[] hashText = Sha256.hash(message);
        String hashedText = Sha256.bytesToHex(hashText);
        System.out.println("\nHashed Message with SHA-256 : " + hashedText);

        KeyPair keyPair = Rsa.generateRsaKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        byte[] encryptedText = Rsa.encrypt(hashedText, publicKey);
        String decryptedText = Rsa.decrypt(encryptedText, privateKey);

        System.out.println("Manual Hash & Rsa");
        System.out.println("\nEncrypted Message SHA-256 with RSA : " + Base64.getEncoder().encodeToString(encryptedText));
        System.out.println("Decrypted Message SHA-256 with RSA : " + decryptedText);
        System.out.println("Check equals message : " + hashedText.equals(decryptedText));


        String encryptedTextSignature = RsaWithSha256.sign(message, privateKey);
        boolean checkSignature = RsaWithSha256.Verify(message, encryptedTextSignature, publicKey);
        System.out.println("\nUsing Signature Library (Hash & Rsa handle by Signature)");
        System.out.println("\nEncrypted Message SHA-256 with RSA : " + encryptedTextSignature);
        System.out.println("Check equals message : " + checkSignature);
    }
}
