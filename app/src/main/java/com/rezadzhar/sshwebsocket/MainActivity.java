package com.rezadzhar.sshwebsocket;

import android.app.Activity;
import android.content.Intent;
import android.net.VpnService;
import android.app.AlertDialog;
import android.os.Bundle;
import android.graphics.Color;
import android.text.SpannableStringBuilder;
import android.text.Spanned;
import android.text.style.ForegroundColorSpan;
import android.text.style.StyleSpan;
import android.text.InputType;
import android.view.View;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.ScrollView;
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
    
    private EditText sshHost, sshPort, sshUser, sshPassword;
    private EditText wsHost, wsPort, wsPayload, fingerprint;
    private CheckBox wsTls;
    private TextView status, observedFingerprint;
    private TextView logView;
    private Button saveButton, connectButton, clearButton, logClearButton, vpnButton;
    private final LogMonitor logMonitor = TunnelState.get().log();
    private TunnelManager getManager() { return TunnelState.get().manager(); }
    private static final int COLOR_GREEN = 0xFF4CAF50;
    private static final int COLOR_YELLOW = 0xFFFFC107;
    private static final int COLOR_RED = 0xFFF44336;
    private static final int COLOR_GRAY = 0xFF8A97A8;
    private static final String DIVIDER;
    static {
        StringBuilder b = new StringBuilder(32);
        for (int i = 0; i < 32; i++) b.append('\u2500');
        DIVIDER = b.toString();
    }
    private boolean busy;
    private boolean TunnelVpnRunning;

    @Override protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        final android.os.Handler uiHandler = new android.os.Handler(android.os.Looper.getMainLooper());
        Thread.setDefaultUncaughtExceptionHandler((t, e) -> uiHandler.post(() -> {
            android.widget.LinearLayout box = new android.widget.LinearLayout(this);
            box.setOrientation(android.widget.LinearLayout.VERTICAL);
            android.widget.TextView tv = new android.widget.TextView(this);
            java.io.StringWriter sw = new java.io.StringWriter();
            e.printStackTrace(new java.io.PrintWriter(sw));
            String msg = sw.toString();
            if (msg.length() > 4000) msg = msg.substring(0, 4000);
            tv.setText("CRASH:\n" + msg);
            tv.setTextSize(10);
            tv.setTypeface(android.graphics.Typeface.MONOSPACE);
            box.addView(tv);
            setContentView(box);
        }));
        try {
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
        logView = findViewById(R.id.log_view);
        logView.setMovementMethod(new android.text.method.ScrollingMovementMethod());
        logClearButton = findViewById(R.id.log_clear_button);
        vpnButton = findViewById(R.id.vpn_button);
        vpnButton.setOnClickListener(v -> toggleVpn());
        logClearButton.setOnClickListener(v -> {
            logMonitor.clear();
            logView.setText("");
            appendLogLine("Log dibersihkan", COLOR_GRAY, false);
            logMonitor.log("Log dibersihkan");
        });
        logMonitor.attach(line -> runOnUiThread(() -> appendLogLine(line, 0, true)), false);
        logView.setText(DIVIDER + "\n" + "Log siap. Tekan Hubungkan SSH untuk mulai." + "\n" + DIVIDER);

        saveButton.setOnClickListener(v -> saveProfile());
        connectButton.setOnClickListener(v -> toggleConnection());
        clearButton.setOnClickListener(v -> confirmClear());
        loadProfile();
        refreshUi();
        } catch (Throwable e) {
            Thread.getDefaultUncaughtExceptionHandler().uncaughtException(Thread.currentThread(), e);
        }
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
        if (busy || getManager().isConnected()) return;
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
        if (getManager().isConnected()) {
            busy = true;
            status.setText(R.string.status_disconnecting);
            refreshUi();
            logMonitor.stopPing();
            worker.execute(() -> {
                getManager().disconnect();
                runOnUiThread(() -> {
                    busy = false;
                    status.setText(R.string.status_disconnected);
                    refreshUi();
                    logMonitor.log("Terputus");
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
        logMonitor.log("Menghubungkan ke " + profile.wsHost + ":" + profile.wsPort
                + (profile.wsTls ? " (TLS)" : ""));
        profile.setHandshakeLogger(() -> logMonitor.log("WebSocket handshake OK"));
        worker.execute(() -> {
            try {
                getManager().connect(profile, logMonitor);
                runOnUiThread(() -> {
                    busy = false;
                    status.setText(R.string.status_connected);
                    refreshUi();
                    logMonitor.log("Connected (SOCKS5 127.0.0.1:1080)");
                    logMonitor.startPing(profile.wsHost, profile.wsPort, new LogMonitor.PingCallback() {
                        @Override public void onPing(long ms) {
                            runOnUiThread(() -> appendLogLine("[PING] " + ms + " ms", 0, true));
                        }
                        @Override public void onPingFail() {
                            runOnUiThread(() -> appendLogLine("[PING] gagal (timeout)", COLOR_RED, true));
                        }
                    });
                });
            } catch (Exception e) {
                String observed = getManager().getObservedFingerprint();
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

    private void appendLogLine(String line, int color, boolean autoScroll) {
        if (logView.length() > 0) logView.append("\n" + DIVIDER + "\n");
        SpannableStringBuilder sb = new SpannableStringBuilder(line);
        int colorToUse = color;
        if (colorToUse == 0) {
            if (line.contains("[PING]")) {
                colorToUse = COLOR_GRAY;
                java.util.regex.Matcher m = java.util.regex.Pattern
                        .compile("(\\d+) ms").matcher(line);
                if (m.find()) {
                    int ms = Integer.parseInt(m.group(1));
                    colorToUse = ms < 200 ? COLOR_GREEN : ms <= 500 ? COLOR_YELLOW : COLOR_RED;
                    sb.setSpan(new ForegroundColorSpan(colorToUse), m.start(), m.end(),
                            Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
                }
            } else if (line.contains("Connected") || line.contains("Terhubung")
                    || line.contains("SOCKS5 aktif")) {
                colorToUse = COLOR_GREEN;
                sb.setSpan(new StyleSpan(android.graphics.Typeface.BOLD), 0, line.length(),
                        Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
            }
        }
        if (colorToUse != 0 && !line.contains("[PING]")) {
            sb.setSpan(new ForegroundColorSpan(colorToUse), 0, line.length(),
                    Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
        }
        logView.append(sb);
        if (autoScroll) logView.post(() -> {
            int offset = logView.getLayout() != null ? logView.getLayout().getLineTop(logView.getLineCount()) : 0;
            if (offset > logView.getHeight()) logView.scrollTo(0, offset - logView.getHeight());
            else logView.scrollTo(0, 0);
        });
    }

    private void toggleVpn() {
        if (busy) return;
        final SshProfile profile;
        try { profile = readForm(); ProfileVault.save(this, profile); }
        catch (Exception e) { status.setText(e.getMessage() == null ? getString(R.string.input_required) : e.getMessage()); return; }
        if (TunnelVpnRunning) {
            stopService(new Intent(this, TunnelVpnService.class));
            TunnelVpnRunning = false;
            status.setText(R.string.status_disconnected);
            logMonitor.log("VPN dimatikan");
            refreshUi();
            return;
        }
        TunnelState.get().setProfile(profile);
        Intent i = new Intent(this, TunnelVpnService.class);
        i.putExtra(TunnelVpnService.EXTRA_PROFILE, profile);
        startActivityForResult(VpnService.prepare(this), 77);
    }

    @Override protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == 77) {
            if (resultCode == RESULT_OK) {
                TunnelVpnRunning = true;
                SshProfile p = TunnelState.get().profile();
                Intent i = new Intent(this, TunnelVpnService.class);
                i.putExtra(TunnelVpnService.EXTRA_PROFILE, p);
                startService(i);
                status.setText("VPN mode: menyambungkan...");
                logMonitor.log("VPN mode: start");
            } else {
                status.setText("Izin VPN ditolak");
            }
            refreshUi();
        }
    }

    private void refreshUi() {
        boolean connected = getManager().isConnected();
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
        if (busy || getManager().isConnected() || !ProfileVault.exists(this)) return;
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
            logMonitor.stopPing();
            logMonitor.detach();
            getManager().disconnect();
            worker.shutdownNow();
        }
    }
}
