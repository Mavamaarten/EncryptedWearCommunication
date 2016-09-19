package com.icapps.encryptedwearcommunication.crypto;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Created by maartenvangiel on 16/09/16.
 */
public class EncryptedDataStream {

    private StreamListener listener;

    private DataInputStream dataInputStream;
    private DataOutputStream dataOutputStream;
    private DHExchange dhExchange;

    private Cipher encryptCipher;
    private Cipher decryptCipher;

    private byte[] sharedSecret;
    private State state = State.NOT_EXCHANGED;

    public EncryptedDataStream(InputStream inputStream, OutputStream outputStream, int keySize, StreamListener listener) {
        this.listener = listener;
        this.dataInputStream = new DataInputStream(inputStream);
        this.dataOutputStream = new DataOutputStream(outputStream);
        dhExchange = new DHExchange(keySize);
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
            final byte[] encryptedData = encryptCipher.doFinal(data);
            dataOutputStream.writeInt(encryptedData.length);
            dataOutputStream.write(encryptedData);
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
            byte[] receivedPublicKeyBytes = new byte[dataInputStream.readInt()];
            dataInputStream.readFully(receivedPublicKeyBytes);
            final DHPublicKey receivedPublicKey = DHUtils.bytesToPublicKey(dhExchange.getPublicKey().getParams(), receivedPublicKeyBytes);
            dhExchange.setReceivedPublicKey(receivedPublicKey);
        } catch (IOException ex) {
            callback.onKeyExchangeFailed(ex);
            return;
        }

        // Generate common secret
        try {
            sharedSecret = shortenSecretKey(dhExchange.generateCommonSecretKey()); // generate key and shorten to 8 bytes for DES

            final SecretKeySpec secretKeySpec = new SecretKeySpec(sharedSecret, "DES");
            encryptCipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
            encryptCipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
            decryptCipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
            decryptCipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException ex) {
            callback.onKeyExchangeFailed(ex);
            return;
        }

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

                final byte[] data = new byte[dataInputStream.readInt()];
                dataInputStream.readFully(data);

                listener.onDataReceived(decryptCipher.doFinal(data));
            } catch (IOException | BadPaddingException | IllegalBlockSizeException e) {
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

    private byte[] shortenSecretKey(final byte[] longKey) {
        try {
            final byte[] shortenedKey = new byte[8];
            System.arraycopy(longKey, 0, shortenedKey, 0, shortenedKey.length);
            return shortenedKey;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
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
