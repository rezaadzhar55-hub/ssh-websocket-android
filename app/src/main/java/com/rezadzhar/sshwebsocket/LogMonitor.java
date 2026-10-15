package com.rezadzhar.sshwebsocket;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.ArrayDeque;
import java.util.Deque;

/** Ring buffer log + TCP-connect ping monitor, pola gaya HTTP Injector. */
final class LogMonitor {
    interface Listener { void onLine(String line); }
    static final int MAX_LINES = 400;
    private static final int DIVIDER = 32;
    private final Deque<String> lines = new ArrayDeque<>();
    private volatile Listener listener;
    private volatile boolean pingRunning;
    private Thread pingThread;
    private volatile PingCallback pingCallback;

    interface PingCallback { void onPing(long ms); void onPingFail(); }

    synchronized void attach(Listener l, boolean includeHistory) {
        listener = l;
        if (includeHistory) for (String line : lines) l.onLine(line);
    }
    synchronized void detach() { listener = null; }

    synchronized void clear() { lines.clear(); }

    void log(String text) {
        String line = "[" + SshProfile.now() + "] " + text;
        synchronized (this) {
            if (!lines.isEmpty()) lines.addLast(divider());
            lines.addLast(line);
            while (lines.size() > MAX_LINES) lines.removeFirst();
        }
        Listener l = listener;
        if (l != null) {
            l.onLine(divider());
            l.onLine(line);
        }
    }

    private static String divider() {
        StringBuilder b = new StringBuilder(DIVIDER);
        for (int i = 0; i < DIVIDER; i++) b.append('\u2500');
        return b.toString();
    }

    void startPing(String host, int port, PingCallback cb) {
        stopPing();
        pingRunning = true;
        pingCallback = cb;
        pingThread = new Thread(() -> {
            while (pingRunning) {
                long ms = -1;
                try {
                    long t0 = System.currentTimeMillis();
                    Socket s = new Socket();
                    s.connect(new InetSocketAddress(host, port), 5000);
                    s.close();
                    ms = System.currentTimeMillis() - t0;
                } catch (IOException ignored) { }
                PingCallback c = pingCallback;
                if (c != null) { if (ms >= 0) c.onPing(ms); else c.onPingFail(); }
                try { Thread.sleep(30_000); } catch (InterruptedException e) { return; }
            }
        }, "ws-ping-monitor");
        pingThread.setDaemon(true);
        pingThread.start();
    }

    void stopPing() {
        pingRunning = false;
        Thread t = pingThread;
        if (t != null) t.interrupt();
        pingThread = null;
        pingCallback = null;
    }
}
