package com.icapps.encryptedwearcommunication.service;

import android.os.Bundle;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.util.Log;

import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.common.api.ResultCallback;
import com.google.android.gms.wearable.Channel;
import com.google.android.gms.wearable.Wearable;
import com.google.android.gms.wearable.WearableListenerService;
import com.icapps.encryptedwearcommunication.crypto.EncryptedDataStream;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Created by maartenvangiel on 15/09/16.
 */
public class MainService extends WearableListenerService implements GoogleApiClient.ConnectionCallbacks, GoogleApiClient.OnConnectionFailedListener, EncryptedDataStream.StreamListener {

    private static String TAG = "WearableService";

    private GoogleApiClient mGoogleApiClient;
    private EncryptedDataStream encryptedDataStream;

    int pongResponseCount = 0;

    @Override
    public void onCreate() {
        super.onCreate();
        System.out.println();
        Log.d(TAG, "Service created");

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
    public void onChannelOpened(final Channel channel) {
        super.onChannelOpened(channel);
        Log.d(TAG, "Channel opened");

        channel.getOutputStream(mGoogleApiClient).setResultCallback(new ResultCallback<Channel.GetOutputStreamResult>() {
            @Override
            public void onResult(@NonNull final Channel.GetOutputStreamResult getOutputStreamResult) {
                channel.getInputStream(mGoogleApiClient).setResultCallback(new ResultCallback<Channel.GetInputStreamResult>() {
                    @Override
                    public void onResult(@NonNull Channel.GetInputStreamResult getInputStreamResult) {
                        onStreamsOpened(getInputStreamResult.getInputStream(), getOutputStreamResult.getOutputStream());
                    }
                });
            }
        });
    }

    private void onStreamsOpened(InputStream inputStream, OutputStream outputStream) {
        encryptedDataStream = new EncryptedDataStream(inputStream, outputStream, 512, this);
        encryptedDataStream.performKeyExchange(new EncryptedDataStream.KeyExchangeCallback() {
            @Override
            public void onKeyExchangeCompleted() {
                encryptedDataStream.startListening(MainService.this);
            }

            @Override
            public void onKeyExchangeFailed(Exception exception) {
                Log.d(TAG, "Key exchange failed", exception);
            }
        });
    }

    @Override
    public void onStateChanged(EncryptedDataStream.State newState) {
        Log.d(TAG, newState.name());
    }

    @Override
    public void onDataReceived(byte[] data) {
        final String receivedMessage = new String(data);
        Log.d(TAG, "Received message: " + receivedMessage);

        if (encryptedDataStream == null) return;
        if (encryptedDataStream.getState() != EncryptedDataStream.State.LISTENING)
            return;

        try {
            String messageToSend = "Pong! " + ++pongResponseCount;
            encryptedDataStream.sendData(messageToSend.getBytes());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    public void onStreamException(Exception ex) {
        Log.d(TAG, "Stream exception", ex);
    }
}
