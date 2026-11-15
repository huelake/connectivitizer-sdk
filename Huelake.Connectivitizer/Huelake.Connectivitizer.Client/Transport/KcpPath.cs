using System.Net;
using Huelake.Connectivitizer.Protocol;
using KcpSharp;

namespace Huelake.Connectivitizer.Client.Transport;

/// <summary>
/// A reliable, ordered byte stream to one peer over UDP (KCP in stream mode). It provides
/// delivery only: confidentiality and peer authentication come from the TLS layer above it.
/// </summary>
internal sealed class KcpPath : IKcpTransport, IAsyncDisposable
{
    private static readonly TimeSpan FlushOnCloseTimeout = TimeSpan.FromSeconds(2);
    private static readonly TimeSpan DrainOnRemoteCloseTimeout = TimeSpan.FromSeconds(3);
    private const int CloseRepeats = 4;
    private static readonly TimeSpan CloseSpacing = TimeSpan.FromMilliseconds(50);

    private readonly UdpPort _port;
    private readonly IPEndPoint _remote;
    private readonly KcpConversation _conversation;
    private readonly KcpStream _kcpStream;
    private readonly CancellationTokenSource _stop = new();
    private readonly Task _maintenance;
    private long _lastReceived;
    private long _lastSent;
    private int _closeState; // 0 = open, 1 = closed
    private volatile string? _closeReason;

    private readonly bool _ownsPort;

    /// <param name="ownsPort">True when closing the path should also close the UDP socket.</param>
    public KcpPath(UdpPort port, IPEndPoint remote, uint conversationId, bool ownsPort = false)
    {
        _ownsPort = ownsPort;
        _port = port;
        _remote = remote;
        _lastReceived = _lastSent = Environment.TickCount64;
        _conversation = new KcpConversation(this, unchecked((int)conversationId), new KcpConversationOptions
        {
            // One byte in front of every KCP packet is reserved for the datagram type.
            Mtu = KcpParameters.MaxDatagramSize,
            PreBufferSize = 1,
            StreamMode = KcpParameters.StreamMode,
            NoDelay = KcpParameters.NoDelay,
            UpdateInterval = KcpParameters.UpdateIntervalMs,
            FastResend = KcpParameters.FastResend,
            DisableCongestionControl = KcpParameters.DisableCongestionControl,
            SendWindow = KcpParameters.SendWindow,
            ReceiveWindow = KcpParameters.ReceiveWindow,
        });
        _kcpStream = new KcpStream(_conversation, ownsConversation: false);
        Stream = new PathStream(this);
        _port.BindPeer(remote, OnDatagramAsync);
        _maintenance = Task.Run(MaintenanceLoopAsync);
    }

    public Stream Stream { get; }

    public IPEndPoint RemoteEndPoint => _remote;

    /// <summary>Receives hole-punch probes that still arrive from the peer after the path was selected.</summary>
    public DatagramHandler? ProbeHandler { get; init; }

    /// <summary>Null while the path is open; afterwards the <see cref="ErrorCodes"/> value explaining why it ended.</summary>
    public string? CloseReason => _closeReason;

    ValueTask IKcpTransport.SendPacketAsync(Memory<byte> packet, CancellationToken cancellationToken)
    {
        packet.Span[0] = DatagramType.Kcp;
        Volatile.Write(ref _lastSent, Environment.TickCount64);
        return _port.SendAsync(packet, _remote, cancellationToken);
    }

    private ValueTask OnDatagramAsync(ReadOnlyMemory<byte> datagram, IPEndPoint remote)
    {
        Volatile.Write(ref _lastReceived, Environment.TickCount64);
        switch (datagram.Span[0])
        {
            case DatagramType.Kcp:
                return Volatile.Read(ref _closeState) == 0
                    ? _conversation.InputPakcetAsync(datagram[1..], _stop.Token)
                    : default;
            case DatagramType.Close:
                _ = CloseAfterDrainAsync();
                return default;
            case DatagramType.Probe or DatagramType.ProbeAck when ProbeHandler is { } probes:
                return probes(datagram, remote);
            default:
                // Keep-alives only refresh the timestamps.
                return default;
        }
    }

    private async Task MaintenanceLoopAsync()
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(1));
        byte[] keepAlive = [DatagramType.KeepAlive];
        try
        {
            while (await timer.WaitForNextTickAsync(_stop.Token).ConfigureAwait(false))
            {
                long now = Environment.TickCount64;
                if (now - Volatile.Read(ref _lastReceived) > KcpParameters.IdleTimeoutMs)
                {
                    Close(ErrorCodes.PathIdleTimeout);
                    return;
                }
                if (now - Volatile.Read(ref _lastSent) > KcpParameters.KeepAliveIntervalMs)
                {
                    Volatile.Write(ref _lastSent, now);
                    await _port.SendAsync(keepAlive, _remote, _stop.Token).ConfigureAwait(false);
                }
            }
        }
        catch (OperationCanceledException)
        {
        }
    }

    /// <summary>The peer announced it is done: let the reader consume what already arrived, then end the stream.</summary>
    private async Task CloseAfterDrainAsync()
    {
        long deadline = Environment.TickCount64 + (long)DrainOnRemoteCloseTimeout.TotalMilliseconds;
        while (Volatile.Read(ref _closeState) == 0 && Environment.TickCount64 < deadline && HasUnreadData())
        {
            await Task.Delay(20).ConfigureAwait(false);
        }
        Close(ErrorCodes.PathClosed);
    }

    private bool HasUnreadData()
    {
        try
        {
            return _conversation.TryPeek(out KcpConversationReceiveResult pending) && pending.BytesReceived > 0;
        }
        catch (InvalidOperationException)
        {
            // KCP refuses to peek while a read is waiting, and a read only waits when nothing is buffered.
            return false;
        }
    }

    private void Close(string reason)
    {
        if (Interlocked.Exchange(ref _closeState, 1) != 0)
        {
            return;
        }
        _closeReason = reason;
        _port.UnbindPeer(_remote);
        _conversation.SetTransportClosed();
        _stop.Cancel();
    }

    public async ValueTask DisposeAsync()
    {
        if (Volatile.Read(ref _closeState) == 0)
        {
            // Give data that was already written a chance to reach the peer, then tell it we are done.
            try
            {
                using var flushTimeout = new CancellationTokenSource(FlushOnCloseTimeout);
                await _conversation.FlushAsync(flushTimeout.Token).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is OperationCanceledException or IOException or ObjectDisposedException)
            {
            }

            // Nothing confirms this datagram, and a busy peer whose socket buffer is still full of
            // retransmissions drops what arrives: copies spread over a moment spare it the idle timeout.
            byte[] close = [DatagramType.Close];
            for (int i = 0; i < CloseRepeats; i++)
            {
                if (i > 0)
                {
                    await Task.Delay(CloseSpacing).ConfigureAwait(false);
                }
                await _port.SendAsync(close, _remote).ConfigureAwait(false);
            }
        }

        Close(ErrorCodes.PathClosed);
        try
        {
            await _maintenance.ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
        }
        _conversation.Dispose();
        _stop.Dispose();
        if (_ownsPort)
        {
            await _port.DisposeAsync().ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Adapts the KCP conversation to the <see cref="System.IO.Stream"/> contract SslStream expects:
    /// a closed path reads as end-of-stream (or an <see cref="IOException"/> on timeout) and
    /// synchronous flushes are harmless no-ops.
    /// </summary>
    private sealed class PathStream(KcpPath path) : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (buffer.IsEmpty)
            {
                return 0;
            }

            int read;
            Exception? failure = null;
            try
            {
                read = await path._kcpStream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is IOException or ObjectDisposedException && path._closeReason is not null)
            {
                read = 0;
                failure = ex;
            }

            // A read that was already waiting when the path ended completes with 0 instead of throwing,
            // so the reason has to be checked in both cases: only an orderly close is an end-of-stream.
            if (read == 0 && path._closeReason is { } reason && reason != ErrorCodes.PathClosed)
            {
                throw new IOException($"The direct path was lost ({reason}).", failure);
            }
            return read;
        }

        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            try
            {
                await path._kcpStream.WriteAsync(buffer, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is IOException or ObjectDisposedException && path._closeReason is { } reason)
            {
                throw new IOException($"The direct path is closed ({reason}).", ex);
            }
        }

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

        // KCP sends on its own timer; there is nothing to push synchronously.
        public override void Flush()
        {
        }

        public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;

        public override int Read(byte[] buffer, int offset, int count) => ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

        public override void Write(byte[] buffer, int offset, int count) => WriteAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override ValueTask DisposeAsync() => path.DisposeAsync();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                path.DisposeAsync().AsTask().GetAwaiter().GetResult();
            }
            base.Dispose(disposing);
        }
    }
}
