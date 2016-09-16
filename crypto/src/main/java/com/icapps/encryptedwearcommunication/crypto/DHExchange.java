package com.icapps.encryptedwearcommunication.crypto;

import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;

/**
 * Created by maartenvangiel on 16/09/16.
 */
public class DHExchange {

    private DHPrivateKey privateKey;
    private DHPublicKey publicKey;
    private DHPublicKey receivedPublicKey;

    public DHExchange(int keySize) {
        generateKeys(keySize);
    }

    private void generateKeys(int keySize) {
        final DHUtils.DHKeyPair keyPair = DHUtils.generateKeyPair(keySize);
        privateKey = keyPair.getPrivateKey();
        publicKey = keyPair.getPublicKey();
    }

    public DHPublicKey getPublicKey() {
        return publicKey;
    }

    public void setReceivedPublicKey(DHPublicKey receivedPublicKey) {
        this.receivedPublicKey = receivedPublicKey;
    }

    public byte[] generateCommonSecretKey() {
        return DHUtils.computeSharedKey(privateKey, receivedPublicKey);
    }
}
