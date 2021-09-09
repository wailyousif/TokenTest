package com.company;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;

public class Token {

    public static SignatureKeys generateSignatureKey() throws NoSuchAlgorithmException {
        KeyPair keyPair = RSA.generateKeyPair(Constants.Security.RSA_TRANSACTION_KEY_SIZE);
        String signingKey = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
        byte[] signatureVerificationKey = keyPair.getPublic().getEncoded();
        return new SignatureKeys(signingKey, signatureVerificationKey);
    }
}
