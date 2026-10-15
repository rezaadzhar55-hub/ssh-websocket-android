package com.rezadzhar.sshwebsocket;

import android.app.Activity;
import android.app.AlertDialog;
import android.os.Bundle;
import android.text.InputType;
import android.view.View;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class MainActivity extends Activity {
    private final ExecutorService worker = Executors.newSingleThreadExecutor(r -> {
        Thread thread = new Thread(r, "ssh-connection-worker");
        thread.setDaemon(true);
        return thread;
    });
    private final TunnelManager manager = new TunnelManager();
    private EditText sshHost, sshPort, sshUser, sshPassword;
    private EditText wsHost, wsPort, wsPayload, fingerprint;
    private CheckBox wsTls;
    private TextView status, observedFingerprint;
    private Button saveButton, connectButton, clearButton;
    private boolean busy;

    @Override protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        sshHost = findViewById(R.id.ssh_host);
        sshPort = findViewById(R.id.ssh_port);
        sshUser = findViewById(R.id.ssh_user);
        sshPassword = findViewById(R.id.ssh_password);
        wsHost = findViewById(R.id.ws_host);
        wsPort = findViewById(R.id.ws_port);
        wsTls = findViewById(R.id.ws_tls);
        wsPayload = findViewById(R.id.ws_payload);
        fingerprint = findViewById(R.id.host_fingerprint);
        status = findViewById(R.id.status);
        observedFingerprint = findViewById(R.id.observed_fingerprint);
        saveButton = findViewById(R.id.save_button);
        connectButton = findViewById(R.id.connect_button);
        clearButton = findViewById(R.id.clear_button);

        saveButton.setOnClickListener(v -> saveProfile());
        connectButton.setOnClickListener(v -> toggleConnection());
        clearButton.setOnClickListener(v -> confirmClear());
        loadProfile();
        refreshUi();
    }

    @Override protected void onResume() {
        super.onResume();
        refreshUi();
    }

    private void loadProfile() {
        try {
            SshProfile profile = ProfileVault.load(this);
            if (profile == null) {
                sshPort.setText("22");
                wsPort.setText("443");
                wsPayload.setText(getString(R.string.default_payload));
                return;
            }
            sshHost.setText(profile.sshHost);
            sshPort.setText(Integer.toString(profile.sshPort));
            sshUser.setText(profile.username);
            sshPassword.setText(profile.password);
            wsHost.setText(profile.wsHost);
            wsPort.setText(Integer.toString(profile.wsPort));
            wsTls.setChecked(profile.wsTls);
            wsPayload.setText(profile.payload);
            fingerprint.setText(profile.fingerprint);
        } catch (Exception e) {
            status.setText("Profil tidak dapat dibaca. Hapus profil tersimpan lalu buat ulang.");
        }
    }

    private SshProfile readForm() {
        int sshPortValue = parsePort(sshPort.getText().toString(), 22);
        int wsPortValue = parsePort(wsPort.getText().toString(), 443);
        SshProfile profile = new SshProfile(value(sshHost), sshPortValue, value(sshUser),
                sshPassword.getText().toString(), value(wsHost), wsPortValue,
                wsTls.isChecked(), wsPayload.getText().toString(), value(fingerprint));
        profile.validate();
        return profile;
    }

    private int parsePort(String text, int fallback) {
        String value = text.trim();
        if (value.isEmpty()) return fallback;
        try { return Integer.parseInt(value); }
        catch (NumberFormatException e) { throw new IllegalArgumentException("Port harus berupa angka 1–65535."); }
    }

    private static String value(EditText field) { return field.getText().toString().trim(); }

    private void saveProfile() {
        if (busy || manager.isConnected()) return;
        try {
            SshProfile profile = readForm();
            ProfileVault.save(this, profile);
            status.setText(R.string.profile_saved);
            Toast.makeText(this, R.string.profile_saved, Toast.LENGTH_SHORT).show();
            refreshUi();
        } catch (Exception e) {
            status.setText(e.getMessage() == null ? getString(R.string.input_required) : e.getMessage());
        }
    }

    private void toggleConnection() {
        if (busy) return;
        if (manager.isConnected()) {
            busy = true;
            status.setText(R.string.status_disconnecting);
            refreshUi();
            worker.execute(() -> {
                manager.disconnect();
                runOnUiThread(() -> {
                    busy = false;
                    status.setText(R.string.status_disconnected);
                    refreshUi();
                });
            });
            return;
        }
        final SshProfile profile;
        try {
            profile = readForm();
            ProfileVault.save(this, profile);
        } catch (Exception e) {
            status.setText(e.getMessage() == null ? getString(R.string.input_required) : e.getMessage());
            return;
        }
        busy = true;
        observedFingerprint.setText("");
        status.setText(R.string.status_connecting);
        refreshUi();
        worker.execute(() -> {
            try {
                manager.connect(profile);
                runOnUiThread(() -> {
                    busy = false;
                    status.setText(R.string.status_connected);
                    refreshUi();
                });
            } catch (Exception e) {
                String observed = manager.getObservedFingerprint();
                runOnUiThread(() -> {
                    busy = false;
                    if (observed != null && !observed.isEmpty()) {
                        observedFingerprint.setText(getString(R.string.observed_prefix) + observed);
                        status.setText(R.string.fingerprint_required);
                    } else if (e.getMessage() != null && e.getMessage().contains("Fingerprint")) {
                        status.setText(e.getMessage());
                    } else {
                        String message = e.getMessage();
                        status.setText("Gagal tersambung: " + (message == null ? "periksa jaringan, payload, dan kredensial." : message));
                    }
                    refreshUi();
                });
            }
        });
    }

    private void refreshUi() {
        boolean connected = manager.isConnected();
        if (connected && !busy) status.setText(R.string.status_connected);
        connectButton.setText(connected ? R.string.disconnect : R.string.connect);
        connectButton.setEnabled(!busy);
        saveButton.setEnabled(!busy && !connected);
        clearButton.setEnabled(!busy && !connected && ProfileVault.exists(this));
        setFieldsEnabled(!busy && !connected);
    }

    private void setFieldsEnabled(boolean enabled) {
        View[] fields = {sshHost, sshPort, sshUser, sshPassword, wsHost, wsPort, wsTls, wsPayload, fingerprint};
        for (View field : fields) field.setEnabled(enabled);
    }

    private void confirmClear() {
        if (busy || manager.isConnected() || !ProfileVault.exists(this)) return;
        new AlertDialog.Builder(this)
                .setMessage(R.string.confirm_clear)
                .setPositiveButton(R.string.clear_profile, (dialog, which) -> {
                    ProfileVault.clear(this);
                    sshHost.setText(""); sshUser.setText(""); sshPassword.setText("");
                    wsHost.setText(""); fingerprint.setText("");
                    sshPort.setText("22"); wsPort.setText("443");
                    wsTls.setChecked(true);
                    wsPayload.setText(getString(R.string.default_payload));
                    observedFingerprint.setText("");
                    status.setText(R.string.status_disconnected);
                    refreshUi();
                })
                .setNegativeButton(R.string.cancel, null)
                .show();
    }

    @Override protected void onDestroy() {
        super.onDestroy();
        if (isFinishing()) {
            // A disconnected UI must not leave a listener on the loopback proxy.
            manager.disconnect();
            worker.shutdownNow();
        }
    }
}
