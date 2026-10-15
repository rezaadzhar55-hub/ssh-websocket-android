package com.rezadzhar.sshwebsocket;

import com.jcraft.jsch.HostKey;
import com.jcraft.jsch.HostKeyRepository;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.Session;
import com.jcraft.jsch.SocketFactory;
import com.jcraft.jsch.UserInfo;
import android.util.Base64;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.security.MessageDigest;

final class TunnelManager {
    private volatile Session session;
    private volatile SocksProxy socksProxy;
    private volatile String observedFingerprint;

    synchronized void connect(SshProfile profile) throws Exception {
        if (isConnected()) return;
        observedFingerprint = null;
        JSch jsch = new JSch();
        Session candidate = jsch.getSession(profile.username, profile.sshHost, profile.sshPort);
        candidate.setPassword(profile.password);
        candidate.setConfig("StrictHostKeyChecking", "yes");
        candidate.setConfig("PreferredAuthentications", "password,keyboard-interactive");
        candidate.setServerAliveInterval(15_000);
        candidate.setServerAliveCountMax(3);
        candidate.setHostKeyRepository(new FingerprintRepository(profile.fingerprint));
        candidate.setSocketFactory(new SocketFactory() {
            @Override public Socket createSocket(String host, int port) throws IOException {
                return new WebSocketTransportSocket(profile);
            }
            @Override public InputStream getInputStream(Socket socket) throws IOException {
                return socket.getInputStream();
            }
            @Override public OutputStream getOutputStream(Socket socket) throws IOException {
                return socket.getOutputStream();
            }
        });
        try {
            candidate.connect(30_000);
            SocksProxy proxy = new SocksProxy(candidate);
            proxy.start();
            session = candidate;
            socksProxy = proxy;
        } catch (Exception e) {
            candidate.disconnect();
            throw e;
        }
    }

    synchronized void disconnect() {
        SocksProxy proxy = socksProxy;
        socksProxy = null;
        if (proxy != null) proxy.close();
        Session current = session;
        session = null;
        if (current != null) current.disconnect();
    }

    boolean isConnected() {
        Session current = session;
        SocksProxy proxy = socksProxy;
        return current != null && current.isConnected() && proxy != null;
    }

    String getObservedFingerprint() { return observedFingerprint; }

    private final class FingerprintRepository implements HostKeyRepository {
        private final String expected;
        FingerprintRepository(String expected) { this.expected = expected == null ? "" : expected.trim().replaceAll("=+$", ""); }

        @Override public int check(String host, byte[] key) {
            String found = fingerprint(key);
            observedFingerprint = found;
            if (!expected.isEmpty() && expected.equals(found)) return HostKeyRepository.OK;
            return expected.isEmpty() ? HostKeyRepository.NOT_INCLUDED : HostKeyRepository.CHANGED;
        }

        @Override public String toString() {
            return expected.isEmpty()
                    ? "Fingerprint host key belum diisi — salin dari tampilan 'Fingerprint teramati' lalu simpan profil."
                    : "Fingerprint host key TIDAK COCOK — koneksi ditolak (mungkin MITM atau server diganti).";
        }
        @Override public void add(HostKey hostkey, UserInfo userinfo) { }
        @Override public void remove(String host, String type) { }
        @Override public void remove(String host, String type, byte[] key) { }
        @Override public String getKnownHostsRepositoryID() { return "SSH host fingerprint pin"; }
        @Override public HostKey[] getHostKey() { return new HostKey[0]; }
        @Override public HostKey[] getHostKey(String host, String type) { return new HostKey[0]; }

        private String fingerprint(byte[] key) {
            try {
                byte[] digest = MessageDigest.getInstance("SHA-256").digest(key);
                return "SHA256:" + Base64.encodeToString(digest, Base64.NO_WRAP | Base64.NO_PADDING);
            } catch (Exception e) {
                return "";
            }
        }
    }
}
