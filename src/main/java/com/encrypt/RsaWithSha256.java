package com.encrypt;
import java.security.Signature;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class RsaWithSha256 {
    public static Signature signatureInstance;

    public static Signature getInstance() throws Exception {
        if(signatureInstance == null) {
            signatureInstance = Signature.getInstance("SHA256withRSA");
        }

        return signatureInstance;
    }

    public static String sign(String message, PrivateKey privateKey) throws Exception {
        Signature signature = getInstance();
        signature.initSign(privateKey);
        signature.update(message.getBytes());
        byte[] signatureBytes = signature.sign();
        return Base64.getEncoder().encodeToString(signatureBytes);
    }

    public static boolean verify(String message, String signatureMessage, PublicKey publicKey) throws Exception {
        Signature signature = getInstance();
        signature.initVerify(publicKey);
        signature.update(message.getBytes());
        byte[] signatureBytes = Base64.getDecoder().decode(signatureMessage);
        return signature.verify(signatureBytes);
    }
}
