package com.icapps.encryptedwearcommunication.crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * Created by maartenvangiel on 16/09/16.
 */
public class SimpleMessageCrypto {

    private byte[] secretKey;

    public SimpleMessageCrypto(byte[] key) {
        this.secretKey = key;
    }

    public byte[] encryptMessage(final String message) {
        try {
            final SecretKeySpec keySpec = new SecretKeySpec(secretKey, "DES");
            final Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec);

            return cipher.doFinal(message.getBytes("UTF-8"));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public String decryptMessage(final byte[] message) {
        try {
            final SecretKeySpec keySpec = new SecretKeySpec(secretKey, "DES");
            final Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");

            cipher.init(Cipher.DECRYPT_MODE, keySpec);

            return new String(cipher.doFinal(message), "UTF-8");
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

}
