package com.icapps.encryptedwearcommunication.crypto;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * Created by maartenvangiel on 16/09/16.
 */
public class EncryptedDataStream {
    private static final int GCM_NONCE_LENGTH = 12; // in bytes
    private static final int GCM_TAG_LENGTH = 16; // in bytes

    private StreamListener listener;

    private DataInputStream dataInputStream;
    private DataOutputStream dataOutputStream;
    private DHExchange dhExchange;

    private SecretKey sharedSecret;
    private State state = State.NOT_EXCHANGED;
    private SecureRandom secureRandom;

    public EncryptedDataStream(InputStream inputStream, OutputStream outputStream, int keySize, StreamListener listener) {
        this.listener = listener;
        this.dataInputStream = new DataInputStream(inputStream);
        this.dataOutputStream = new DataOutputStream(outputStream);
        dhExchange = new DHExchange(keySize);
        secureRandom = new SecureRandom();
    }

    private void setState(State state) {
        this.state = state;
        listener.onStateChanged(state);
    }

    public State getState() {
        return state;
    }

    public void sendData(byte[] data) throws IOException {
        if (state != State.LISTENING) {
            throw new IllegalStateException("Key exchange nod (yet) performed");
        }

        try {
            // Generate a random IV
            final byte[] iv = new byte[GCM_NONCE_LENGTH];
            secureRandom.nextBytes(iv);

            // Initialize our cipher using the IV and encrypt the data with it
            final AlgorithmParameterSpec algorithmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
            final Cipher encryptCipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
            encryptCipher.init(Cipher.ENCRYPT_MODE, sharedSecret, algorithmParameterSpec);
            encryptCipher.updateAAD("Authentication".getBytes());

            final byte[] encryptedData = encryptCipher.doFinal(data);

            dataOutputStream.writeInt(encryptedData.length);
            dataOutputStream.write(encryptedData);
            dataOutputStream.write(iv);
        } catch (Exception ex) {
            listener.onStreamException(ex);
        }
    }

    public void performKeyExchange(final KeyExchangeCallback callback) {
        if (state == State.LISTENING || state == State.EXCHANGING) {
            callback.onKeyExchangeFailed(new IllegalStateException("Already listening or exchanging"));
        }

        setState(State.EXCHANGING);

        // Send our public key
        try {
            final byte[] encodedPublicKey = DHUtils.keyToBytes(dhExchange.getPublicKey());
            dataOutputStream.writeInt(encodedPublicKey.length);
            dataOutputStream.write(encodedPublicKey);
        } catch (IOException ex) {
            callback.onKeyExchangeFailed(ex);
            return;
        }

        // Receive the other party's public key
        try {
            final byte[] receivedPublicKeyBytes = new byte[dataInputStream.readInt()];
            dataInputStream.readFully(receivedPublicKeyBytes);
            final DHPublicKey receivedPublicKey = DHUtils.bytesToPublicKey(dhExchange.getPublicKey().getParams(), receivedPublicKeyBytes);
            dhExchange.setReceivedPublicKey(receivedPublicKey);
        } catch (IOException ex) {
            callback.onKeyExchangeFailed(ex);
            return;
        }

        // Generate the common secret
        sharedSecret = dhExchange.generateCommonSecretKey();

        setState(State.EXCHANGED);
        callback.onKeyExchangeCompleted();
    }

    public void startListening(final StreamListener listener) {
        if (sharedSecret == null) {
            listener.onStreamException(new IllegalStateException("Key exchange not (yet) performed"));
            return;
        }

        if (state == State.LISTENING) {
            listener.onStreamException(new IllegalStateException("Inputstream thread already running"));
            return;
        }

        setState(EncryptedDataStream.State.LISTENING);

        while (!(Thread.currentThread().isInterrupted() || state == EncryptedDataStream.State.CLOSED)) {
            try {
                if (dataInputStream.available() <= 0) continue;

                // Read the data
                final byte[] data = new byte[dataInputStream.readInt()];
                dataInputStream.readFully(data);

                // Read the IV
                final byte[] iv = new byte[GCM_NONCE_LENGTH];
                dataInputStream.readFully(iv);

                // Initialize cipher using IV and decrypt the data
                final AlgorithmParameterSpec algorithmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
                final Cipher decryptCipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
                decryptCipher.init(Cipher.DECRYPT_MODE, sharedSecret, algorithmParameterSpec);
                decryptCipher.updateAAD("Authentication".getBytes());

                listener.onDataReceived(decryptCipher.doFinal(data));
            } catch (IOException | GeneralSecurityException e) {
                listener.onStreamException(e);
                setState(EncryptedDataStream.State.CLOSED);
                return;
            }
        }

        setState(EncryptedDataStream.State.CLOSED);
    }

    public void stopListening() {
        setState(State.CLOSED);

        try {
            dataInputStream.close();
            dataOutputStream.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public enum State {
        NOT_EXCHANGED,
        EXCHANGING,
        EXCHANGED,
        LISTENING,
        CLOSED
    }

    public interface KeyExchangeCallback {
        void onKeyExchangeCompleted();

        void onKeyExchangeFailed(Exception exception);
    }

    public interface StreamListener {
        void onStateChanged(final State newState);

        void onDataReceived(final byte[] data);

        void onStreamException(final Exception ex);
    }
}
