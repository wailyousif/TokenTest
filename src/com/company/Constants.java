package com.company;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class Constants {

    public static class Security {
        public static final List<String> SECURE_HTTP_HEADERS = new ArrayList<>(Arrays.asList("Authorization"));

        public static final int RSA_TRANSACTION_KEY_SIZE = 512;

        public static final String ALG_RSA = "RSA";
        public static final String ALG_RSA_ECB_PCKS1PADDING = "RSA/ECB/PKCS1Padding";
        public static final String ALG_AES = "AES";
        public static final String ALG_AES_ECB_PKCS5PADDING = "AES/ECB/PKCS5Padding";

        public static final String SHA2_384 = "SHA-384";
    }
}
