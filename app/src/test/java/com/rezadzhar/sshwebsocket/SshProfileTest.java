package com.rezadzhar.sshwebsocket;

import org.junit.Test;
import static org.junit.Assert.assertThrows;

public class SshProfileTest {
    private static final String PAYLOAD = "GET / HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf]Sec-WebSocket-Key: [key][crlf]Sec-WebSocket-Version: 13[crlf][crlf]";

    private SshProfile profile(int sshPort, int wsPort, String payload, String fingerprint) {
        return new SshProfile("vps.example", sshPort, "user", "password", "ws.example", wsPort,
                true, payload, fingerprint);
    }

    @Test public void acceptsValidTcpWebSocketProfileWithoutPinForDiscovery() {
        profile(22, 443, PAYLOAD, "").validate();
    }

    @Test public void rejectsOutOfRangePorts() {
        assertThrows(IllegalArgumentException.class, () -> profile(70000, 443, PAYLOAD, "").validate());
        assertThrows(IllegalArgumentException.class, () -> profile(22, 0, PAYLOAD, "").validate());
    }

    @Test public void rejectsPayloadWithoutDynamicWebSocketKey() {
        assertThrows(IllegalArgumentException.class,
                () -> profile(22, 443, "GET / HTTP/1.1[crlf]Upgrade: websocket[crlf][crlf]", "").validate());
    }

    @Test public void rejectsMalformedFingerprint() {
        assertThrows(IllegalArgumentException.class, () -> profile(22, 443, PAYLOAD, "MD5:1234").validate());
    }
}
