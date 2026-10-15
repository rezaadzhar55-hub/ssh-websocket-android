package com.rezadzhar.sshwebsocket;

public final class TunnelState {
    private static final TunnelState INSTANCE = new TunnelState();
    private final TunnelManager manager = new TunnelManager();
    private final LogMonitor log = new LogMonitor();
    private volatile SshProfile profile;

    public static TunnelState get() { return INSTANCE; }
    public TunnelManager manager() { return manager; }
    public LogMonitor log() { return log; }
    public SshProfile profile() { return profile; }
    public void setProfile(SshProfile p) { this.profile = p; }
}
