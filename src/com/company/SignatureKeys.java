package com.company;

public class SignatureKeys {

    private String signingKey;
    private byte[] signatureVerificationKey;

    public SignatureKeys() { }

    public SignatureKeys(String signingKey, byte[] signatureVerificationKey) {
        this.signingKey = signingKey;
        this.signatureVerificationKey = signatureVerificationKey;
    }

    public String getSigningKey() {
        return signingKey;
    }

    public void setSigningKey(String signingKey) {
        this.signingKey = signingKey;
    }

    public byte[] getSignatureVerificationKey() {
        return signatureVerificationKey;
    }

    public void setSignatureVerificationKey(byte[] signatureVerificationKey) {
        this.signatureVerificationKey = signatureVerificationKey;
    }
}
