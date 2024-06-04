package com.encrypt;

import java.security.MessageDigest;

public class Sha256 {
    private static MessageDigest digest;

    public static MessageDigest getInstance() throws Exception {
        if (digest == null) {
            digest = MessageDigest.getInstance("SHA-256");
        }

        return digest;
    }

    public static byte[] hash(String message) throws Exception {
        byte[] encodedHash = getInstance().digest(message.getBytes());
        return encodedHash;
    }

    public static String bytesToHex(byte[] hash) {
        StringBuilder hexString = new StringBuilder(2 * hash.length);

        for (int i = 0; i < hash.length; ++i) {
            String hex = Integer.toHexString(255 & hash[i]);
            if (hex.length() == 1) {
                hexString.append('0');
            }

            hexString.append(hex);
        }

        return hexString.toString();
    }
}