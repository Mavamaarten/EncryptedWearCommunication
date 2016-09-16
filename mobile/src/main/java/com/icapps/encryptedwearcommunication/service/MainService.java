package com.icapps.encryptedwearcommunication.service;

import android.os.Bundle;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.util.Base64;
import android.util.Log;

import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.common.api.ResultCallback;
import com.google.android.gms.wearable.Channel;
import com.google.android.gms.wearable.Wearable;
import com.google.android.gms.wearable.WearableListenerService;
import com.icapps.encryptedwearcommunication.crypto.DHExchange;
import com.icapps.encryptedwearcommunication.crypto.DHUtils;
import com.icapps.encryptedwearcommunication.crypto.SimpleMessageCrypto;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

import javax.crypto.interfaces.DHPublicKey;

/**
 * Created by maartenvangiel on 15/09/16.
 */
public class MainService extends WearableListenerService implements GoogleApiClient.ConnectionCallbacks, GoogleApiClient.OnConnectionFailedListener {

    private static String TAG = "WearableService";
    private GoogleApiClient mGoogleApiClient;

    private DataInputStream inputStream;
    private DataOutputStream outputStream;

    private DHExchange dhExchange;
    private SimpleMessageCrypto messageCrypto;

    int pongResponseCount = 0;

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

    @Override
    public void onCreate() {
        super.onCreate();
        System.out.println();
        Log.d(TAG, "Service created");

        dhExchange = new DHExchange(512);

        if (mGoogleApiClient == null) {
            mGoogleApiClient = new GoogleApiClient.Builder(this)
                    .addApi(Wearable.API)
                    .addConnectionCallbacks(this)
                    .addOnConnectionFailedListener(this)
                    .build();
        }

        if (!mGoogleApiClient.isConnected()) {
            mGoogleApiClient.connect();
        }
    }

    @Override
    public void onDestroy() {
        if (mGoogleApiClient != null) {
            mGoogleApiClient.disconnect();
        }
        Log.d(TAG, "Service destroyed");
        System.out.println();
        super.onDestroy();
    }

    @Override
    public void onConnected(@Nullable Bundle bundle) {
        Log.d(TAG, "Connected");
    }

    @Override
    public void onConnectionSuspended(int i) {
        Log.d(TAG, "Connection suspended");
    }

    @Override
    public void onConnectionFailed(@NonNull ConnectionResult connectionResult) {
        Log.d(TAG, "Connection failed");
    }

    @Override
    public void onChannelOpened(Channel channel) {
        super.onChannelOpened(channel);
        Log.d(TAG, "Channel opened");

        channel.getOutputStream(mGoogleApiClient).setResultCallback(new ResultCallback<Channel.GetOutputStreamResult>() {
            @Override
            public void onResult(@NonNull Channel.GetOutputStreamResult getOutputStreamResult) {
                outputStream = new DataOutputStream(getOutputStreamResult.getOutputStream());

                new Thread(new Runnable() {
                    @Override
                    public void run() {
                        onOutputStreamOpened();
                    }
                }).start();
            }
        });
        channel.getInputStream(mGoogleApiClient).setResultCallback(new ResultCallback<Channel.GetInputStreamResult>() {
            @Override
            public void onResult(@NonNull Channel.GetInputStreamResult getInputStreamResult) {
                inputStream = new DataInputStream(getInputStreamResult.getInputStream());

                new Thread(new Runnable() {
                    @Override
                    public void run() {
                        onInputStreamOpened();
                    }
                }).start();
            }
        });
    }

    private void onOutputStreamOpened() {
        try {
            Log.d(TAG, "Output stream opened - Sending phone public key");

            // Send our public key to watch
            final byte[] encodedPublicKey = DHUtils.keyToBytes(dhExchange.getPublicKey());
            outputStream.writeInt(encodedPublicKey.length);
            outputStream.write(encodedPublicKey);

            Log.d(TAG, "Public phone key sent: " + Base64.encodeToString(encodedPublicKey, Base64.NO_WRAP));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void onInputStreamOpened() {
        try {
            Log.d(TAG, "Inputstream opened - Receiving watch public key");

            // Read phone public key
            byte[] receivedPublicKeyBytes = new byte[inputStream.readInt()];
            inputStream.readFully(receivedPublicKeyBytes);

            final DHPublicKey receivedPublicKey = DHUtils.bytesToPublicKey(dhExchange.getPublicKey().getParams(), receivedPublicKeyBytes);
            dhExchange.setReceivedPublicKey(receivedPublicKey);

            Log.d(TAG, "Received watch public key: " + Base64.encodeToString(receivedPublicKeyBytes, Base64.NO_WRAP));

            // Generate common secret
            final byte[] shortenedCommonSecret = shortenSecretKey(dhExchange.generateCommonSecretKey());
            messageCrypto = new SimpleMessageCrypto(shortenedCommonSecret);

            // Listen for encrypted messages
            while (!Thread.currentThread().isInterrupted()) {
                if(inputStream.available() > 0){
                    byte[] receivedBytes = new byte[inputStream.readInt()];
                    inputStream.readFully(receivedBytes);

                    String decryptedMessage = messageCrypto.decryptMessage(receivedBytes);
                    Log.d(TAG, "Received message: \"" + decryptedMessage + "\"");

                    byte[] encryptedResponse = messageCrypto.encryptMessage("Pong! " + ++pongResponseCount);
                    outputStream.writeInt(encryptedResponse.length);
                    outputStream.write(encryptedResponse);
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                inputStream.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    @Override
    public void onChannelClosed(Channel channel, int i, int i1) {
        super.onChannelClosed(channel, i, i1);
        Log.d(TAG, "Channel closed");
    }

    @Override
    public void onInputClosed(Channel channel, int i, int i1) {
        super.onInputClosed(channel, i, i1);
        Log.d(TAG, "Input closed");
    }

    @Override
    public void onOutputClosed(Channel channel, int i, int i1) {
        super.onOutputClosed(channel, i, i1);
        Log.d(TAG, "Output closed");
    }
}
