package com.encrypt;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class HmacAlgorithm {
    public static String hmacAlgorithm(String data, String secretKey, String algorithm) throws Exception {
        SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getBytes(), algorithm);
        Mac mac = Mac.getInstance(algorithm);
        mac.init(secretKeySpec);
        
        byte[] hashedData = mac.doFinal(data.getBytes());

        return Base64.getEncoder().encodeToString(hashedData);
    }
}
