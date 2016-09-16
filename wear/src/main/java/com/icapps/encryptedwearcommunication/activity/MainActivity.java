package com.icapps.encryptedwearcommunication.activity;

import android.app.Activity;
import android.os.Bundle;
import android.os.Handler;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.wearable.view.WatchViewStub;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.TextView;

import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.common.api.ResultCallback;
import com.google.android.gms.wearable.Channel;
import com.google.android.gms.wearable.ChannelApi;
import com.google.android.gms.wearable.NodeApi;
import com.google.android.gms.wearable.Wearable;
import com.icapps.hellowearandroid.R;
import com.icapps.encryptedwearcommunication.crypto.DH;
import com.icapps.encryptedwearcommunication.crypto.SimpleMessageCrypto;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;

public class MainActivity extends Activity implements ChannelApi.ChannelListener {

    private static String TAG = "WearableMainActivity";

    private TextView mTextView;
    private GoogleApiClient googleApiClient;

    private DataOutputStream outputStream;
    private DataInputStream inputStream;

    private DHPrivateKey privateKey;
    private DHPublicKey publicKey;
    private DHPublicKey receivedPublicKey;

    private SimpleMessageCrypto messageCrypto;

    int pingRequestCount = 0;

    private void generateKeys() {
        Log.d(TAG, "Generating watch secret key");

        try {
            final DH.DHKeyPair keyPair = DH.generateKeyPair(512);

            privateKey = keyPair.getPrivateKey();
            publicKey = keyPair.getPublicKey();

            Log.d(TAG, "Generated watch secret key");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void generateCommonSecretKey() {
        Log.d(TAG, "Generating common secret key");

        try {
            final byte[] secretKey = shortenSecretKey(DH.computeSharedKey(privateKey, receivedPublicKey));
            messageCrypto = new SimpleMessageCrypto(secretKey);

            Log.d(TAG, "Generated common secret key!");
        } catch (Exception e) {
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

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        final WatchViewStub stub = (WatchViewStub) findViewById(R.id.watch_view_stub);
        stub.setOnLayoutInflatedListener(new WatchViewStub.OnLayoutInflatedListener() {
            @Override
            public void onLayoutInflated(WatchViewStub stub) {
                mTextView = (TextView) stub.findViewById(R.id.text);
                mTextView.setOnClickListener(new View.OnClickListener() {
                    @Override
                    public void onClick(View view) {
                        if (messageCrypto == null) return;

                        byte[] encryptedMessage = messageCrypto.encryptMessage("Ping " + ++pingRequestCount);
                        try {
                            outputStream.writeInt(encryptedMessage.length);
                            outputStream.write(encryptedMessage);
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                    }
                });
            }
        });
    }

    @Override
    protected void onStart() {
        super.onStart();

        googleApiClient = new GoogleApiClient.Builder(this)
                .addConnectionCallbacks(new GoogleApiClient.ConnectionCallbacks() {
                    @Override
                    public void onConnected(@Nullable Bundle bundle) {
                        Log.d(TAG, "Google API connected");
                        Wearable.ChannelApi.addListener(googleApiClient, MainActivity.this);
                        tryOpenChannel();
                    }

                    @Override
                    public void onConnectionSuspended(int i) {
                        Log.d(TAG, "Google API suspended");
                    }
                }).addOnConnectionFailedListener(new GoogleApiClient.OnConnectionFailedListener() {
                    @Override
                    public void onConnectionFailed(@NonNull ConnectionResult connectionResult) {
                        Log.d(TAG, "Google API connection failed");
                    }
                }).addApi(Wearable.API)
                .build();
        googleApiClient.connect();
    }

    @Override
    protected void onStop() {
        super.onStop();

        try {
            outputStream.close();
            inputStream.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void tryOpenChannel() {
        Wearable.NodeApi.getConnectedNodes(googleApiClient).setResultCallback(new ResultCallback<NodeApi.GetConnectedNodesResult>() {
            @Override
            public void onResult(@NonNull NodeApi.GetConnectedNodesResult getConnectedNodesResult) {
                if (getConnectedNodesResult.getNodes().size() == 0) {
                    Log.d(TAG, "No connected nodes... trying again in 5s");
                    new Handler().postDelayed(new Runnable() {
                        @Override
                        public void run() {
                            tryOpenChannel();
                        }
                    }, 5000);
                    return;
                }

                Log.d(TAG, "Found a node. Opening channel...");
                String nodeId = getConnectedNodesResult.getNodes().get(0).getId();

                generateKeys();

                Wearable.ChannelApi.openChannel(googleApiClient, nodeId, "/channel").setResultCallback(new ResultCallback<ChannelApi.OpenChannelResult>() {
                    @Override
                    public void onResult(@NonNull ChannelApi.OpenChannelResult openChannelResult) {
                        onChannelOpened(openChannelResult.getChannel());
                    }
                });
            }
        });
    }

    @Override
    public void onChannelOpened(Channel channel) {
        Log.d(TAG, "Channel opened");

        channel.getOutputStream(googleApiClient).setResultCallback(new ResultCallback<Channel.GetOutputStreamResult>() {
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
        channel.getInputStream(googleApiClient).setResultCallback(new ResultCallback<Channel.GetInputStreamResult>() {
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

    public void onOutputStreamOpened() {
        try {
            Log.d(TAG, "Output stream opened - Sending watch public key");

            final byte[] encodedPublicKey = DH.keyToBytes(publicKey);

            outputStream.writeInt(encodedPublicKey.length);
            outputStream.write(encodedPublicKey);

            Log.d(TAG, "Public watch key sent: " + Base64.encodeToString(encodedPublicKey, Base64.NO_WRAP));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void onInputStreamOpened() {
        try {
            Log.d(TAG, "Inputstream opened - Receiving watch public key");

            byte[] receivedPublicKeyBytes = new byte[inputStream.readInt()];
            inputStream.readFully(receivedPublicKeyBytes);

            this.receivedPublicKey = DH.bytesToPublicKey(publicKey.getParams(), receivedPublicKeyBytes);

            Log.d(TAG, "Received phone public key: " + Base64.encodeToString(receivedPublicKeyBytes, Base64.NO_WRAP));

            generateCommonSecretKey();

            while (!Thread.currentThread().isInterrupted()) {
                if(inputStream.available() > 0){
                    byte[] receivedBytes = new byte[inputStream.readInt()];
                    inputStream.readFully(receivedBytes);

                    final String decryptedMessage = messageCrypto.decryptMessage(receivedBytes);

                    runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            mTextView.setText("Received message: \"" + decryptedMessage + "\"");
                        }
                    });
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    public void onChannelClosed(Channel channel, int i, int i1) {
        Log.d(TAG, "Channel closed");
    }

    @Override
    public void onInputClosed(Channel channel, int i, int i1) {
        Log.d(TAG, "Input closed");
    }

    @Override
    public void onOutputClosed(Channel channel, int i, int i1) {
        Log.d(TAG, "Output closed");
    }
}
