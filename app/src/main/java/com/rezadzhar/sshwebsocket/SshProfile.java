package com.rezadzhar.sshwebsocket;

import org.json.JSONException;
import org.json.JSONObject;

final class SshProfile {
    final String sshHost;
    final int sshPort;
    final String username;
    final String password;
    final String wsHost;
    final int wsPort;
    final boolean wsTls;
    final String payload;
    final String fingerprint;
    transient Runnable handshakeLogger;

    SshProfile(String sshHost, int sshPort, String username, String password,
               String wsHost, int wsPort, boolean wsTls, String payload, String fingerprint) {
        this.sshHost = clean(sshHost);
        this.sshPort = sshPort;
        this.username = clean(username);
        this.password = password == null ? "" : password;
        this.wsHost = clean(wsHost);
        this.wsPort = wsPort;
        this.wsTls = wsTls;
        this.payload = payload == null ? "" : payload;
        this.fingerprint = normalizeFingerprint(fingerprint);
    }

    void validate() {
        if (sshHost.isEmpty() || wsHost.isEmpty() || username.isEmpty() || password.isEmpty()) {
            throw new IllegalArgumentException("Host SSH/WebSocket, username, dan password wajib diisi.");
        }
        if (sshPort < 1 || sshPort > 65535 || wsPort < 1 || wsPort > 65535) {
            throw new IllegalArgumentException("Port harus berada pada rentang 1–65535.");
        }
        if (payload.trim().isEmpty() || !payload.toLowerCase(java.util.Locale.ROOT).contains("upgrade: websocket")
                || !payload.contains("[key]") && !payload.contains("{key}")) {
            throw new IllegalArgumentException("Payload harus memuat Upgrade: websocket dan token [key].");
        }
        if (!fingerprint.isEmpty() && !fingerprint.matches("SHA256:[A-Za-z0-9+/]{20,}=?")) {
            throw new IllegalArgumentException("Fingerprint harus berbentuk SHA256:….");
        }
    }

    JSONObject toJson() throws JSONException {
        JSONObject json = new JSONObject();
        json.put("sshHost", sshHost);
        json.put("sshPort", sshPort);
        json.put("username", username);
        json.put("password", password);
        json.put("wsHost", wsHost);
        json.put("wsPort", wsPort);
        json.put("wsTls", wsTls);
        json.put("payload", payload);
        json.put("fingerprint", fingerprint);
        return json;
    }

    static SshProfile fromJson(String text) throws JSONException {
        JSONObject json = new JSONObject(text);
        return new SshProfile(json.optString("sshHost"), json.optInt("sshPort", 22),
                json.optString("username"), json.optString("password"),
                json.optString("wsHost"), json.optInt("wsPort", 443), json.optBoolean("wsTls", true),
                json.optString("payload"), json.optString("fingerprint"));
    }

    void setHandshakeLogger(Runnable r) { this.handshakeLogger = r; }

    static String now() {
        return new java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.US)
                .format(new java.util.Date());
    }

    private static String clean(String value) {
        return value == null ? "" : value.trim();
    }

    private static String normalizeFingerprint(String value) {
        return value == null ? "" : value.trim().replaceAll("=+$", "");
    }
}
