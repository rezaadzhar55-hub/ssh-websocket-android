package com.rezadzhar.sshwebsocket;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import android.util.Base64;
import java.util.Locale;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/** A WebSocket binary stream exposed as the Socket expected by JSch. */
final class WebSocketTransportSocket extends Socket {
    private static final int CONNECT_TIMEOUT_MS = 15_000;
    private static final int MAX_HANDSHAKE_BYTES = 32 * 1024;
    private static final int MAX_MESSAGE_BYTES = 8 * 1024 * 1024;
    private static final int WRITE_CHUNK_BYTES = 16 * 1024;
    private final SecureRandom random = new SecureRandom();
    private final Object writeLock = new Object();
    private Socket transport;
    private InputStream transportIn;
    private OutputStream transportOut;
    private volatile boolean closed;
    private volatile long lastActivity;
    private Thread pingThread;
    private byte[] pending = new byte[0];
    private int pendingOffset;
    private static final int PING_INTERVAL_MS = 25_000;

    WebSocketTransportSocket(SshProfile profile) throws IOException {
        open(profile);
    }

    private void open(SshProfile profile) throws IOException {
        Socket raw = new Socket();
        try {
            raw.connect(new InetSocketAddress(profile.wsHost, profile.wsPort), CONNECT_TIMEOUT_MS);
            raw.setSoTimeout(CONNECT_TIMEOUT_MS);
            if (profile.wsTls) {
                SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
                SSLSocket tls = (SSLSocket) factory
                        .createSocket(raw, profile.wsHost, profile.wsPort, true);
                tls.setUseClientMode(true);
                tls.startHandshake();
                raw = tls;
            }
            transport = raw;
            transportIn = raw.getInputStream();
            transportOut = raw.getOutputStream();
            performHandshake(profile);
            if (profile.handshakeLogger != null) profile.handshakeLogger.run();
            raw.setSoTimeout(0);
            lastActivity = System.currentTimeMillis();
            pingThread = new Thread(this::pingLoop, "ws-ping");
            pingThread.setDaemon(true);
            pingThread.start();
        } catch (IOException | RuntimeException e) {
            try { raw.close(); } catch (IOException ignored) { }
            throw e;
        }
    }

    private void pingLoop() {
        while (!closed) {
            try { Thread.sleep(PING_INTERVAL_MS); } catch (InterruptedException e) { return; }
            if (closed) return;
            if (System.currentTimeMillis() - lastActivity < PING_INTERVAL_MS) continue;
            try { sendFrame(0x9, ("ws-keepalive-" + System.currentTimeMillis()).getBytes(StandardCharsets.US_ASCII)); }
            catch (IOException e) { return; }
        }
    }

    private void performHandshake(SshProfile profile) throws IOException {
        byte[] nonce = new byte[16];
        random.nextBytes(nonce);
        String key = Base64.encodeToString(nonce, Base64.NO_WRAP);
        String request = profile.payload
                .replace("[crlf]", "\r\n").replace("[lf]", "\n")
                .replace("[host]", profile.wsHost).replace("{host}", profile.wsHost)
                .replace("[port]", Integer.toString(profile.wsPort)).replace("{port}", Integer.toString(profile.wsPort))
                .replace("[ssh_host]", profile.sshHost).replace("{ssh_host}", profile.sshHost)
                .replace("[key]", key).replace("{key}", key);
        if (!request.endsWith("\r\n\r\n")) {
            request = request.replaceAll("(?:\\r?\\n)*$", "") + "\r\n\r\n";
        }
        transportOut.write(request.getBytes(StandardCharsets.ISO_8859_1));
        transportOut.flush();

        ByteArrayOutputStream response = new ByteArrayOutputStream();
        int state = 0;
        while (response.size() < MAX_HANDSHAKE_BYTES) {
            int value = transportIn.read();
            if (value < 0) throw new EOFException("Gateway menutup koneksi saat HTTP Upgrade.");
            response.write(value);
            if (state == 0 && value == '\r') state = 1;
            else if (state == 1 && value == '\n') state = 2;
            else if (state == 2 && value == '\r') state = 3;
            else if (state == 3 && value == '\n') break;
            else state = value == '\r' ? 1 : 0;
        }
        if (response.size() >= MAX_HANDSHAKE_BYTES) throw new IOException("Header Upgrade WebSocket terlalu besar.");
        String text = response.toString(StandardCharsets.ISO_8859_1.name());
        String[] lines = text.split("\\r\\n");
        if (lines.length == 0 || !lines[0].matches("HTTP/1\\.[01] 101(?: .*)?")) {
            throw new IOException("Gateway tidak menerima WebSocket Upgrade: " + (lines.length == 0 ? "respons kosong" : lines[0]));
        }
        String accept = null;
        for (int i = 1; i < lines.length; i++) {
            int colon = lines[i].indexOf(':');
            if (colon > 0 && lines[i].substring(0, colon).trim().equalsIgnoreCase("Sec-WebSocket-Accept")) {
                accept = lines[i].substring(colon + 1).trim();
                break;
            }
        }
        String expected;
        try {
            expected = Base64.encodeToString(MessageDigest.getInstance("SHA-1")
                    .digest((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").getBytes(StandardCharsets.ISO_8859_1)), Base64.NO_WRAP);
        } catch (Exception e) {
            throw new IOException("Tidak dapat memvalidasi handshake WebSocket.", e);
        }
        if (accept == null || !expected.equals(accept)) throw new IOException("Sec-WebSocket-Accept tidak cocok; periksa payload/gateway.");
    }

    @Override public InputStream getInputStream() throws IOException {
        if (closed) throw new IOException("WebSocket sudah ditutup.");
        return new InputStream() {
            @Override public int read() throws IOException {
                byte[] one = new byte[1];
                int n = read(one, 0, 1);
                return n < 0 ? -1 : one[0] & 0xff;
            }
            @Override public int read(byte[] buffer, int offset, int length) throws IOException {
                if (buffer == null) throw new NullPointerException();
                if (offset < 0 || length < 0 || length > buffer.length - offset) throw new IndexOutOfBoundsException();
                if (length == 0) return 0;
                if (closed) return -1;
                if (pendingOffset >= pending.length) {
                    pending = readBinaryMessage();
                    pendingOffset = 0;
                    if (pending == null) return -1;
                }
                int count = Math.min(length, pending.length - pendingOffset);
                System.arraycopy(pending, pendingOffset, buffer, offset, count);
                pendingOffset += count;
                return count;
            }
            @Override public void close() throws IOException { WebSocketTransportSocket.this.close(); }
        };
    }

    @Override public OutputStream getOutputStream() throws IOException {
        if (closed) throw new IOException("WebSocket sudah ditutup.");
        return new OutputStream() {
            @Override public void write(int value) throws IOException {
                byte[] one = {(byte) value};
                write(one, 0, 1);
            }
            @Override public void write(byte[] buffer, int offset, int length) throws IOException {
                if (buffer == null) throw new NullPointerException();
                if (offset < 0 || length < 0 || length > buffer.length - offset) throw new IndexOutOfBoundsException();
                if (closed) throw new IOException("WebSocket sudah ditutup.");
                int end = offset + length;
                while (offset < end) {
                    int count = Math.min(WRITE_CHUNK_BYTES, end - offset);
                    byte[] chunk = new byte[count];
                    System.arraycopy(buffer, offset, chunk, 0, count);
                    sendFrame(0x2, chunk);
                    offset += count;
                }
            }
            @Override public void flush() throws IOException {
                if (closed) throw new IOException("WebSocket sudah ditutup.");
                transportOut.flush();
            }
            @Override public void close() throws IOException { WebSocketTransportSocket.this.close(); }
        };
    }

    private byte[] readBinaryMessage() throws IOException {
        ByteArrayOutputStream message = new ByteArrayOutputStream();
        boolean started = false;
        while (true) {
            Frame frame = readFrame();
            if (frame.opcode == 0x8) {
                try { sendFrame(0x8, frame.payload); } catch (IOException ignored) { }
                return null;
            }
            if (frame.opcode == 0x9) {
                sendFrame(0xA, frame.payload);
                continue;
            }
            if (frame.opcode == 0xA) continue;
            if (!started && frame.opcode == 0x2) started = true;
            else if (!started || frame.opcode != 0x0) throw new IOException("Gateway mengirim frame WebSocket non-biner yang tidak didukung.");
            if ((long) message.size() + frame.payload.length > MAX_MESSAGE_BYTES) throw new IOException("Frame WebSocket melebihi batas aman.");
            message.write(frame.payload);
            if (frame.fin) return message.toByteArray();
        }
    }

    private Frame readFrame() throws IOException {
        int first = transportIn.read();
        lastActivity = System.currentTimeMillis();
        if (first < 0) return new Frame(true, 0x8, new byte[0]);
        int second = readRequired();
        boolean fin = (first & 0x80) != 0;
        if ((first & 0x70) != 0) throw new IOException("Ekstensi WebSocket tak terduga.");
        int opcode = first & 0x0f;
        boolean masked = (second & 0x80) != 0;
        long length = second & 0x7f;
        if (length == 126) length = ((long) readRequired() << 8) | readRequired();
        else if (length == 127) {
            length = 0;
            for (int i = 0; i < 8; i++) {
                int b = readRequired();
                if (i == 0 && (b & 0x80) != 0) throw new IOException("Panjang frame WebSocket tidak valid.");
                length = (length << 8) | b;
            }
        }
        if (length > MAX_MESSAGE_BYTES || length > Integer.MAX_VALUE) throw new IOException("Frame WebSocket terlalu besar.");
        if ((opcode & 0x8) != 0 && (!fin || length > 125)) throw new IOException("Frame kontrol WebSocket tidak valid.");
        byte[] mask = masked ? new byte[4] : null;
        if (masked) readFully(mask);
        byte[] payload = new byte[(int) length];
        readFully(payload);
        if (masked) for (int i = 0; i < payload.length; i++) payload[i] ^= mask[i & 3];
        return new Frame(fin, opcode, payload);
    }

    private int readRequired() throws IOException {
        lastActivity = System.currentTimeMillis();
        int value = transportIn.read();
        if (value < 0) throw new EOFException("Frame WebSocket terpotong.");
        return value;
    }

    private void readFully(byte[] bytes) throws IOException {
        int offset = 0;
        while (offset < bytes.length) {
            int count = transportIn.read(bytes, offset, bytes.length - offset);
            if (count < 0) throw new EOFException("Frame WebSocket terpotong.");
            offset += count;
        }
    }

    private void sendFrame(int opcode, byte[] payload) throws IOException {
        synchronized (writeLock) {
            if (closed && opcode != 0x8) throw new IOException("WebSocket sudah ditutup.");
            int length = payload.length;
            ByteArrayOutputStream header = new ByteArrayOutputStream(14);
            header.write(0x80 | (opcode & 0x0f));
            if (length < 126) header.write(0x80 | length);
            else if (length <= 0xffff) {
                header.write(0x80 | 126);
                header.write((length >>> 8) & 0xff);
                header.write(length & 0xff);
            } else {
                header.write(0x80 | 127);
                long value = length;
                for (int shift = 56; shift >= 0; shift -= 8) header.write((int) (value >>> shift) & 0xff);
            }
            byte[] mask = new byte[4];
            random.nextBytes(mask);
            header.write(mask);
            lastActivity = System.currentTimeMillis();
            transportOut.write(header.toByteArray());
            byte[] maskedPayload = new byte[length];
            for (int i = 0; i < length; i++) maskedPayload[i] = (byte) (payload[i] ^ mask[i & 3]);
            transportOut.write(maskedPayload);
            transportOut.flush();
        }
    }

    @Override public void close() throws IOException {
        if (closed) return;
        closed = true;
        Thread pinger = pingThread;
        if (pinger != null) pinger.interrupt();
        IOException failure = null;
        try {
            synchronized (writeLock) {
                if (transportOut != null && transport != null && !transport.isClosed()) {
                    byte[] closePayload = new byte[] {(byte) 0x03, (byte) 0xe8};
                    byte[] mask = new byte[4];
                    random.nextBytes(mask);
                    transportOut.write(new byte[] {(byte) 0x88, (byte) (0x80 | closePayload.length), mask[0], mask[1], mask[2], mask[3],
                            (byte) (closePayload[0] ^ mask[0]), (byte) (closePayload[1] ^ mask[1])});
                    transportOut.flush();
                }
            }
        } catch (IOException e) { failure = e; }
        try { if (transport != null) transport.close(); }
        catch (IOException e) { if (failure == null) failure = e; }
        if (failure != null) throw failure;
    }

    @Override public boolean isConnected() { return transport != null && transport.isConnected(); }
    @Override public boolean isClosed() { return closed || transport == null || transport.isClosed(); }
    @Override public void setSoTimeout(int timeout) {
        if (transport != null) try { transport.setSoTimeout(timeout); } catch (IOException e) { throw new IllegalStateException(e); }
    }
    @Override public int getSoTimeout() {
        if (transport == null) return 0;
        try { return transport.getSoTimeout(); } catch (IOException e) { throw new IllegalStateException(e); }
    }
    @Override public void setTcpNoDelay(boolean on) { }
    @Override public void setKeepAlive(boolean on) {
        if (transport != null) try { transport.setKeepAlive(on); } catch (IOException e) { throw new IllegalStateException(e); }
    }
    @Override public SocketAddress getRemoteSocketAddress() { return transport == null ? null : transport.getRemoteSocketAddress(); }

    private static final class Frame {
        final boolean fin;
        final int opcode;
        final byte[] payload;
        Frame(boolean fin, int opcode, byte[] payload) { this.fin = fin; this.opcode = opcode; this.payload = payload; }
    }
}
