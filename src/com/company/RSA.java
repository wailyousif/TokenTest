package com.company;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class RSA {

    public static KeyPair generateKeyPair(int keySize) throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(Constants.Security.ALG_RSA);
        keyPairGenerator.initialize(keySize);
        return keyPairGenerator.generateKeyPair();
    }

    public static byte[] process(int encryptOrDecrypt, String operationMode,
                                 int publicOrPrivateKey, byte[] keyBytes, byte[] dataBytes) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Key key = null;
        KeyFactory keyFactory = KeyFactory.getInstance(Constants.Security.ALG_RSA);
        if (publicOrPrivateKey == Cipher.PUBLIC_KEY)
        {
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(keyBytes);   //X509EncodedKeySpec public key encoding
            key = keyFactory.generatePublic(x509EncodedKeySpec);
        }
        else
        {
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(keyBytes);    //PKCS8EncodedKeySpec private key encoding
            key = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        }

        Cipher cipher = Cipher.getInstance(operationMode);
        cipher.init(encryptOrDecrypt, key);
        byte[] outputBytes = cipher.doFinal(dataBytes);
        return outputBytes;
    }
}
