namespace Huelake.Connectivitizer.Protocol;

/// <summary>
/// Values fixed by the wire protocol (see docs/protocol). Every implementation in every
/// language must use exactly these; changing one is a protocol version change.
/// </summary>
public static class WireConstants
{
    /// <summary>ALPN identifier of the end-to-end TLS layer.</summary>
    public const string TunnelAlpn = "cz-tunnel/1";

    /// <summary>
    /// Constant TLS server name used inside the tunnel. Peers are authenticated by their
    /// certificate's public key, never by name, so the name carries no information.
    /// </summary>
    public const string TunnelServerName = "cz-tunnel";

    /// <summary>Prefix of an identity fingerprint: SHA-256 over the certificate's SubjectPublicKeyInfo, lower-case hex.</summary>
    public const string FingerprintPrefix = "sha256:";
}

/// <summary>
/// First byte of every datagram exchanged directly between two peers. The values sit in
/// 0xC0-0xCF so they can never be mistaken for STUN (first byte 0x00-0x03).
/// </summary>
public static class DatagramType
{
    public const byte Probe = 0xC1;
    public const byte ProbeAck = 0xC2;
    public const byte Kcp = 0xC3;
    public const byte KeepAlive = 0xC4;
    public const byte Close = 0xC5;
}

/// <summary>Framing of a direct TCP path before the end-to-end layer starts (protocol section 7).</summary>
public static class TcpPath
{
    /// <summary>First byte of the hello both sides send on a new connection. Followed by the 8-byte session tag and the sender's role.</summary>
    public const byte Hello = 0xC6;
    public const int HelloSize = 10;
    public const byte RoleInitiator = 1;
    public const byte RoleDevice = 2;

    /// <summary>Sent by the initiator on the connection it chose, and echoed by the device.</summary>
    public const byte Select = 0x01;
}

/// <summary>KCP parameters both peers of a direct UDP path must use.</summary>
public static class KcpParameters
{
    /// <summary>Largest datagram a peer may send, including the one-byte <see cref="DatagramType"/>.</summary>
    public const int MaxDatagramSize = 1200;

    /// <summary>KCP runs in stream mode: segment boundaries carry no meaning.</summary>
    public const bool StreamMode = true;

    public const bool NoDelay = true;
    public const int UpdateIntervalMs = 10;
    public const int FastResend = 2;
    public const bool DisableCongestionControl = true;
    public const int SendWindow = 256;
    public const int ReceiveWindow = 256;

    /// <summary>A peer sends a keep-alive datagram when it has sent nothing else for this long.</summary>
    public const int KeepAliveIntervalMs = 15_000;

    /// <summary>A path with no datagram received for this long is considered dead.</summary>
    public const int IdleTimeoutMs = 45_000;
}
