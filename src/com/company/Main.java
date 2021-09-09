package com.company;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Base64;
import java.util.UUID;

public class Main {

    static SignatureKeys signatureKeys;

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, InvalidKeySpecException, IllegalBlockSizeException, NoSuchPaddingException {
        generateAndValidateToken();
    }

    static void generateAndValidateToken() throws NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, InvalidKeySpecException, NoSuchPaddingException {
        String date = getHttpDate();
        System.out.println("HttpDate:" + date);

        String purePhoneNumber = "901239310";
        String transId = "9493e1a6-7f69-4385-a5cd-8d535d3c7dc2";
        String requestBody = "{\n" +
                "    \"newHashedPin\": \"hashpintest2\"\n" +
                "}";
        String deviceId = "handsetId1";

        signatureKeys = Token.generateSignatureKey();
        //String privateKey = signatureKeys.getSigningKey();
        String privateKey = "MIIBUwIBADANBgkqhkiG9w0BAQEFAASCAT0wggE5AgEAAkEAjW87Jr1vminFbtrSWaqDTje/0bPw8ttk+IIMWY5WwnFOT2+2wO3/BwdBjpY+jTOhNi1pBcf8qHVx1vyzB1LtHwIDAQABAkAF2tnvA56QGjSTHznf/mALJ+Gn87QAybZHV1LdjjfnOqvKCETxK5xWXRCRnZTKa9pSp1ascIhbzuyMGbkRqU0RAiEAws/YyUo73deqBags/tth/2jm1gVIcBOZtxatR5MOldkCIQC52328Ws6sRlmnmHSIopDsxUl38QDvuOCaSfTpe8fntwIgYPAR/J+uyIX/OY9kzHCYBALMEqVQVUy7iYqEMQBxGokCID8ubY0FdbK866d8vUjhstC6tKIQjNfxinEI6TgiOy/7AiAz61lC5tZGlow4NTfVacE7HaelXlnWnPABjROrGWTXsQ==";
        System.out.println("Private key:" + privateKey);

        String publicKey = "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAI1vOya9b5opxW7a0lmqg043v9Gz8PLbZPiCDFmOVsJxTk9vtsDt/wcHQY6WPo0zoTYtaQXH/Kh1cdb8swdS7R8CAwEAAQ==";
        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKey);
        //byte[] publicKeyBytes = signatureKeys.getSignatureVerificationKey();


        String message = date + purePhoneNumber + transId + requestBody + deviceId;

        byte[] token = generateTheToken(message, privateKey);

        //String tokenString = new String(token, StandardCharsets.UTF_8);
        String tokenString = Base64.getEncoder().encodeToString(token);
        System.out.println("tokenString:" + tokenString);
        System.out.println("requestBody:\n" + requestBody);

        boolean validToken = isValidToken(tokenString, message, publicKeyBytes);
        System.out.println("validToken: " + validToken);
    }

    public static boolean isValidToken(String token, String message, byte[] signatureVerificationKey) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidKeySpecException {
        byte[] tokenBytes = Base64.getDecoder().decode(token);
        byte[] decryptedTokenBytes = RSA.process(Cipher.DECRYPT_MODE, Constants.Security.ALG_RSA_ECB_PCKS1PADDING,
                Cipher.PUBLIC_KEY, signatureVerificationKey, tokenBytes);
        byte[] hashBytes = Hashing.getSHA2(Constants.Security.SHA2_384, message.getBytes(StandardCharsets.UTF_8));
        if (Arrays.equals(hashBytes, decryptedTokenBytes)) {
            return true;
        }
        return false;
    }

    public static String getHttpDate() {
        return DateTimeFormatter.RFC_1123_DATE_TIME.format(ZonedDateTime.now(ZoneOffset.UTC));
    }


    public static byte[] generateTheToken(String message, String privateKey) {
        try {
            // getInstance() method is called with algorithm SHA-384
            MessageDigest md = MessageDigest.getInstance("SHA-384");

            // digest() method is called
            // to calculate message digest of the input string
            // returned as array of byte
            byte[] messageBytesUTF8 = message.getBytes(StandardCharsets.UTF_8);

            byte[] messageHashBytes = md.digest(messageBytesUTF8);

            //encrypt the message with the private key
            PrivateKey key = generatePrivateKey(privateKey);
            Cipher encryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            encryptCipher.init(Cipher.ENCRYPT_MODE, key);
            // encrypt it with the private key
            byte[] tokenBytes = encryptCipher.doFinal(messageHashBytes);

            // return it as Base64 encoding
            //return Base64.encode(tokenBytes, Base64.NO_WRAP);
            return tokenBytes;
        }

        // For specifying wrong message digest algorithms
        catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeySpecException | InvalidKeyException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return null;
    }


    static PrivateKey generatePrivateKey(String privateKey) throws NoSuchAlgorithmException,
            InvalidKeySpecException {

        // Base64 decode the result
        //byte[] pkcs8EncodedBytes = Base64.decode(privateKey, Base64.DEFAULT);
        byte[] pkcs8EncodedBytes = Base64.getDecoder().decode(privateKey);

        // extract the private key
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pkcs8EncodedBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");

        // return the privateKey
        return kf.generatePrivate(keySpec);
    }

}
