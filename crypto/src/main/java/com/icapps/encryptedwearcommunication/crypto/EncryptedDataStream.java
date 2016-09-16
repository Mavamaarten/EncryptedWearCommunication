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

    private DataInputStream inputStream;
    private DataOutputStream outputStream;
    private DHExchange dhExchange;

    private SendPublicKeyThread sendPublicKeyThread;
    private ReceivePublicKeyThread receivePublicKeyThread;
    private InputStreamThread inputStreamThread;

    private SecretKeySpec secretKeySpec;
    private Cipher cipher;

    private byte[] sharedSecret;
    private State state = State.NOT_EXCHANGED;

    public EncryptedDataStream(InputStream inputStream, OutputStream outputStream, int keySize, StreamListener listener) {
        this.listener = listener;
        this.inputStream = new DataInputStream(inputStream);
        this.outputStream = new DataOutputStream(outputStream);
        dhExchange = new DHExchange(keySize);
    }

    private void setState(State state){
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
            final byte[] encryptedData = cipher.doFinal(data);
            outputStream.writeInt(encryptedData.length);
            outputStream.write(encryptedData);
        } catch (BadPaddingException | IllegalBlockSizeException e) {
            throw new SecurityException("Error encrypting data", e);
        }
    }

    public void performKeyExchange(final KeyExchangeCallback callback) {
        if ((sendPublicKeyThread != null && sendPublicKeyThread.isAlive()) ||
                (receivePublicKeyThread != null && receivePublicKeyThread.isAlive())) {
            callback.onKeyExchangeFailed(new IllegalStateException("Key exchange already in progress"));
            return;
        }

        sendPublicKeyThread = new SendPublicKeyThread(callback);
        sendPublicKeyThread.start();

        receivePublicKeyThread = new ReceivePublicKeyThread(callback);
        receivePublicKeyThread.start();

        setState(State.EXCHANGING);
    }

    public void startListening(final StreamListener listener) {
        if (sharedSecret == null) {
            listener.onStreamException(new IllegalStateException("Key exchange not (yet) performed"));
            return;
        }

        if (inputStreamThread != null && inputStreamThread.isAlive()) {
            listener.onStreamException(new IllegalStateException("Inputstream thread already running"));
            return;
        }

        inputStreamThread = new InputStreamThread();
        inputStreamThread.start();
    }

    public void stopListening(){
        if(sendPublicKeyThread != null){
            sendPublicKeyThread.interrupt();
        }
        if(receivePublicKeyThread != null){
            receivePublicKeyThread.interrupt();
        }
        if(inputStreamThread != null){
            inputStreamThread.interrupt();
        }
        try{
            inputStream.close();
            outputStream.close();
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

    public class ReceivePublicKeyThread extends Thread {
        private KeyExchangeCallback callback;

        public ReceivePublicKeyThread(KeyExchangeCallback callback) {
            this.callback = callback;
        }

        @Override
        public void run() {
            try {
                byte[] receivedPublicKeyBytes = new byte[inputStream.readInt()];
                inputStream.readFully(receivedPublicKeyBytes);
                final DHPublicKey receivedPublicKey = DHUtils.bytesToPublicKey(dhExchange.getPublicKey().getParams(), receivedPublicKeyBytes);
                dhExchange.setReceivedPublicKey(receivedPublicKey);

                sharedSecret = shortenSecretKey(dhExchange.generateCommonSecretKey());

                secretKeySpec = new SecretKeySpec(sharedSecret, "DES");
                cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

                callback.onKeyExchangeCompleted();
            } catch (IOException | InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException e) {
                callback.onKeyExchangeFailed(e);
                setState(EncryptedDataStream.State.CLOSED);
            }
        }
    }

    public class SendPublicKeyThread extends Thread {
        private KeyExchangeCallback callback;

        public SendPublicKeyThread(KeyExchangeCallback callback) {
            this.callback = callback;
        }

        @Override
        public void run() {
            try {
                final byte[] encodedPublicKey = DHUtils.keyToBytes(dhExchange.getPublicKey());
                outputStream.writeInt(encodedPublicKey.length);
                outputStream.write(encodedPublicKey);
            } catch (IOException e) {
                callback.onKeyExchangeFailed(e);
                setState(EncryptedDataStream.State.CLOSED);
            }
        }
    }

    public class InputStreamThread extends Thread {

        @Override
        public void run() {
            final SecretKeySpec keySpec = new SecretKeySpec(sharedSecret, "DES");
            final Cipher cipher;
            try {
                cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
                cipher.init(Cipher.DECRYPT_MODE, keySpec);
            } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
                listener.onStreamException(e);
                return;
            }

            setState(EncryptedDataStream.State.LISTENING);

            while (!interrupted()) {
                try {
                    if (inputStream.available() <= 0) continue;

                    final byte[] data = new byte[inputStream.readInt()];
                    inputStream.readFully(data);
                    listener.onDataReceived(cipher.doFinal(data));
                } catch (IOException | BadPaddingException | IllegalBlockSizeException e) {
                    listener.onStreamException(e);
                    setState(EncryptedDataStream.State.CLOSED);
                    return;
                }
            }
        }
    }

    public enum State {
        NOT_EXCHANGED,
        EXCHANGING,
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
