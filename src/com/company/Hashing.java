package com.company;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Hashing {

    public static byte[] getSHA2(String algorithm, byte[] bytesToHash) throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance(algorithm);
        byte[] hashBytes = messageDigest.digest(bytesToHash);
        return hashBytes;
    }
}
