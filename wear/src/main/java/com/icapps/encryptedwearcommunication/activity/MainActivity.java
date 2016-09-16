package com.icapps.encryptedwearcommunication.activity;

import android.app.Activity;
import android.os.Bundle;
import android.os.Handler;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.util.Log;
import android.view.View;
import android.widget.ProgressBar;
import android.widget.TextView;

import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.common.api.ResultCallback;
import com.google.android.gms.wearable.Channel;
import com.google.android.gms.wearable.ChannelApi;
import com.google.android.gms.wearable.NodeApi;
import com.google.android.gms.wearable.Wearable;
import com.icapps.encryptedwearcommunication.R;
import com.icapps.encryptedwearcommunication.crypto.EncryptedDataStream;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class MainActivity extends Activity implements ChannelApi.ChannelListener, EncryptedDataStream.StreamListener {

    private static String TAG = "WearableMainActivity";

    private TextView mTextView;
    private ProgressBar mProgressBar;

    private GoogleApiClient googleApiClient;
    private EncryptedDataStream encryptedDataStream;

    int pingRequestCount = 0;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        mTextView = (TextView) findViewById(R.id.text);
        mTextView.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                if (encryptedDataStream == null) return;
                if (encryptedDataStream.getState() != EncryptedDataStream.State.LISTENING)
                    return;

                try {
                    String messageToSend = "Ping! " + ++pingRequestCount;
                    encryptedDataStream.sendData(messageToSend.getBytes());
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        });

        mProgressBar = (ProgressBar) findViewById(R.id.loading);
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
                })
                .addOnConnectionFailedListener(new GoogleApiClient.OnConnectionFailedListener() {
                    @Override
                    public void onConnectionFailed(@NonNull ConnectionResult connectionResult) {
                        Log.d(TAG, "Google API connection failed");
                    }
                })
                .addApi(Wearable.API)
                .build();
        googleApiClient.connect();
    }

    @Override
    protected void onStop() {
        super.onStop();
        if (encryptedDataStream != null) {
            encryptedDataStream.stopListening();
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
    public void onChannelOpened(final Channel channel) {
        Log.d(TAG, "Channel opened");

        channel.getOutputStream(googleApiClient).setResultCallback(new ResultCallback<Channel.GetOutputStreamResult>() {
            @Override
            public void onResult(@NonNull final Channel.GetOutputStreamResult getOutputStreamResult) {
                channel.getInputStream(googleApiClient).setResultCallback(new ResultCallback<Channel.GetInputStreamResult>() {
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
                encryptedDataStream.startListening(MainActivity.this);
            }

            @Override
            public void onKeyExchangeFailed(Exception exception) {
                Log.d(TAG, "Key exchange failed", exception);
            }
        });
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

    @Override
    public void onStateChanged(final EncryptedDataStream.State newState) {
        Log.d(TAG, newState.name());

        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                if (newState == EncryptedDataStream.State.LISTENING) {
                    mTextView.setVisibility(View.VISIBLE);
                    mProgressBar.setVisibility(View.GONE);
                }
            }
        });
    }

    @Override
    public void onDataReceived(byte[] data) {
        final String receivedMessage = new String(data);
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                mTextView.setText(receivedMessage);
            }
        });
    }

    @Override
    public void onStreamException(Exception ex) {
        Log.d(TAG, "Stream exception", ex);
    }
}
