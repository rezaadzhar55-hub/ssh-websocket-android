package com.rezadzhar.sshwebsocket;

import android.content.Intent;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;
import java.io.File;

public class TunnelVpnService extends VpnService {
    private static final String TAG = "TunnelVPN";
    private Process tun2socks;
    private ParcelFileDescriptor tun;
    private Thread pingThread;
    private volatile boolean running;

    public static final String EXTRA_PROFILE = "profile";

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        SshProfile profile = (SshProfile) intent.getSerializableExtra(EXTRA_PROFILE);
        if (profile == null) {
            stopSelf();
            return START_NOT_STICKY;
        }
        running = true;
        startTunnel(profile);
        return START_STICKY;
    }

    private void startTunnel(SshProfile profile) {
        try {
            // 1. Start SSH tunnel + SOCKS5 (TunnelManager singleton)
            TunnelManager m = TunnelState.get().manager();
            if (!m.isConnected()) {
                m.connect(TunnelState.get().profile(), TunnelState.get().log());
            }
            // 2. Establish TUN
            Builder b = new Builder()
                    .setSession("SSH-WS VPN")
                    .setMtu(1500)
                    .addAddress("26.26.26.1", 24)
                    .addDnsServer("8.8.8.8")
                    .addDnsServer("1.1.1.1")
                    .addRoute("0.0.0.0", 1)
                    .addRoute("128.0.0.0", 1);
            // bypass route ke gateway WS (biar tunnel-nya sendiri tidak lewat VPN)
            bypassGateway(profile);
            tun = b.establish();
            if (tun == null) {
                TunnelState.get().log().log("VPN gagal: izin ditolak");
                stopSelf();
                return;
            }
            TunnelState.get().log().log("VPN TUN aktif (26.26.26.1)");
            // 3. Start tun2socks binary -> SOCKS5 127.0.0.1:1080
            String bin = new File(getApplicationInfo().nativeLibraryDir, "libtun2socks.so").getAbsolutePath();
            ProcessBuilder pb = new ProcessBuilder(bin,
                    "-t", String.valueOf(tun.getFd()),
                    "-R", "socks5://127.0.0.1:1080",
                    "--loglevel", "error");
            pb.redirectErrorStream(true);
            tun2socks = pb.start();
            // 4. Log output tun2socks
            Thread reader = new Thread(() -> {
                try {
                    java.io.BufferedReader r = new java.io.BufferedReader(
                            new java.io.InputStreamReader(tun2socks.getInputStream()));
                    String line;
                    while ((line = r.readLine()) != null) {
                        if (!line.trim().isEmpty()) TunnelState.get().log().log("tun2socks: " + line.trim());
                    }
                } catch (Exception ignored) { }
            }, "tun2socks-log");
            reader.setDaemon(true);
            reader.start();
            TunnelState.get().log().log("Connected (VPN mode)");
            TunnelState.get().log().log("Ping monitor aktif (30s)");
            startPing(profile);
        } catch (Exception e) {
            TunnelState.get().log().log("VPN error: " + e.getMessage());
            stopSelf();
        }
    }

    private void bypassGateway(SshProfile profile) {
        // Resolve gateway & add bypass route
        try {
            java.net.InetAddress[] addrs = java.net.InetAddress.getAllByName(profile.wsHost);
            for (java.net.InetAddress a : addrs) {
                try {
                    protect(a.getAddress());
                } catch (Exception ignored) { }
            }
        } catch (Exception ignored) { }
    }

    private void startPing(SshProfile profile) {
        pingThread = new Thread(() -> {
            while (running) {
                long ms = -1;
                try {
                    long t0 = System.currentTimeMillis();
                    java.net.Socket s = new java.net.Socket();
                    s.connect(new java.net.InetSocketAddress(profile.wsHost, profile.wsPort), 5000);
                    s.close();
                    ms = System.currentTimeMillis() - t0;
                } catch (Exception ignored) { }
                final long f = ms;
                TunnelState.get().log().log(f >= 0 ? "[PING] " + f + " ms" : "[PING] gagal");
                try { Thread.sleep(30_000); } catch (InterruptedException e) { return; }
            }
        }, "vpn-ping");
        pingThread.setDaemon(true);
        pingThread.start();
    }

    @Override public void onDestroy() {
        running = false;
        if (pingThread != null) pingThread.interrupt();
        if (tun2socks != null) tun2socks.destroy();
        if (tun != null) try { tun.close(); } catch (Exception ignored) { }
        TunnelState.get().manager().disconnect();
        TunnelState.get().log().log("VPN mode dimatikan");
        super.onDestroy();
    }
}
