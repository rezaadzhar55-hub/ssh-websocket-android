package com.rezadzhar.sshwebsocket;

import com.jcraft.jsch.Channel;
import com.jcraft.jsch.ChannelDirectTCPIP;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.Session;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

final class SocksProxy implements AutoCloseable {
    static final int LOCAL_PORT = 1080;
    private final Session session;
    private final ExecutorService clients = Executors.newCachedThreadPool(r -> {
        Thread thread = new Thread(r, "ssh-socks-client");
        thread.setDaemon(true);
        return thread;
    });
    private volatile boolean running;
    private ServerSocket server;
    private Thread acceptThread;

    SocksProxy(Session session) { this.session = session; }

    void start() throws IOException {
        server = new ServerSocket();
        server.setReuseAddress(true);
        server.bind(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), LOCAL_PORT), 32);
        running = true;
        acceptThread = new Thread(() -> {
            while (running) {
                try {
                    Socket client = server.accept();
                    clients.execute(() -> handle(client));
                } catch (IOException e) {
                    if (running) close();
                }
            }
        }, "ssh-socks-accept");
        acceptThread.setDaemon(true);
        acceptThread.start();
    }

    private void handle(Socket client) {
        Channel channel = null;
        try (Socket socket = client) {
            socket.setSoTimeout(30_000);
            DataInputStream input = new DataInputStream(socket.getInputStream());
            OutputStream output = socket.getOutputStream();
            int version = input.readUnsignedByte();
            int methodCount = input.readUnsignedByte();
            if (version != 5 || methodCount == 0) return;
            boolean noAuth = false;
            for (int i = 0; i < methodCount; i++) if (input.readUnsignedByte() == 0) noAuth = true;
            output.write(new byte[] {5, (byte) (noAuth ? 0 : 0xff)});
            output.flush();
            if (!noAuth) return;

            int requestVersion = input.readUnsignedByte();
            int command = input.readUnsignedByte();
            input.readUnsignedByte(); // reserved
            int addressType = input.readUnsignedByte();
            String target;
            if (addressType == 1) {
                byte[] address = new byte[4];
                input.readFully(address);
                target = InetAddress.getByAddress(address).getHostAddress();
            } else if (addressType == 3) {
                int length = input.readUnsignedByte();
                byte[] address = new byte[length];
                input.readFully(address);
                target = new String(address, StandardCharsets.US_ASCII);
            } else if (addressType == 4) {
                byte[] address = new byte[16];
                input.readFully(address);
                target = InetAddress.getByAddress(address).getHostAddress();
            } else {
                sendReply(output, 8);
                return;
            }
            int targetPort = input.readUnsignedShort();
            if (requestVersion != 5 || command != 1 || targetPort == 0 || target.isEmpty()) {
                sendReply(output, command == 1 ? 1 : 7);
                return;
            }
            if (!session.isConnected()) {
                sendReply(output, 1);
                return;
            }
            ChannelDirectTCPIP direct = (ChannelDirectTCPIP) session.openChannel("direct-tcpip");
            direct.setHost(target);
            direct.setPort(targetPort);
            direct.setOrgIPAddress(socket.getInetAddress().getHostAddress());
            direct.setOrgPort(socket.getPort());
            channel = direct;
            channel.connect(15_000);
            socket.setSoTimeout(0);
            sendReply(output, 0);
            InputStream remoteInput = channel.getInputStream();
            OutputStream remoteOutput = channel.getOutputStream();
            Channel activeChannel = channel;
            Thread downlink = new Thread(() -> relay(remoteInput, output, socket, activeChannel), "ssh-socks-downlink");
            downlink.setDaemon(true);
            downlink.start();
            relay(input, remoteOutput, socket, activeChannel);
        } catch (Exception e) {
            if (channel == null) {
                try { sendReply(client.getOutputStream(), 1); } catch (Exception ignored) { }
            }
        } finally {
            if (channel != null) channel.disconnect();
        }
    }

    private static void relay(InputStream input, OutputStream output, Socket socket, Channel channel) {
        try {
            byte[] buffer = new byte[16 * 1024];
            int count;
            while ((count = input.read(buffer)) != -1) {
                output.write(buffer, 0, count);
                output.flush();
            }
        } catch (IOException ignored) {
        } finally {
            channel.disconnect();
            try { socket.close(); } catch (IOException ignored) { }
        }
    }

    private static void sendReply(OutputStream output, int result) throws IOException {
        output.write(new byte[] {5, (byte) result, 0, 1, 0, 0, 0, 0, 0, 0});
        output.flush();
    }

    @Override public void close() {
        running = false;
        if (server != null) {
            try { server.close(); } catch (IOException ignored) { }
        }
        clients.shutdownNow();
    }
}
