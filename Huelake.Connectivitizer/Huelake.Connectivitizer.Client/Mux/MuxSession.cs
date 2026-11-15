using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Threading.Channels;
using Huelake.Connectivitizer.Protocol;

namespace Huelake.Connectivitizer.Client.Mux;

/// <summary>
/// Multiplexes many independent byte streams over the one end-to-end encrypted channel of a
/// session, using yamux framing (12-byte header, per-stream flow control). Everything it
/// carries is inside the TLS layer, so stream metadata is as private as the payload.
/// </summary>
public sealed class MuxSession : IAsyncDisposable
{
    internal const int HeaderSize = 12;
    internal const uint InitialWindow = 256 * 1024;
    internal const int MaxFrameData = 16 * 1024;
    private const int MaxStreams = 256;

    private readonly Stream _transport;
    private readonly bool _isInitiator;
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private readonly ConcurrentDictionary<uint, MuxStream> _streams = new();
    private readonly Channel<MuxStream> _incoming = Channel.CreateUnbounded<MuxStream>();
    private readonly CancellationTokenSource _closed = new();
    private readonly TaskCompletionSource<string> _completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly ConcurrentDictionary<uint, TaskCompletionSource> _pings = new();
    private Task? _readLoop;
    private uint _nextStreamId;
    private uint _lastRemoteStreamId;
    private uint _nextPingId;
    private int _disposed;

    /// <param name="transport">The secure stream of the session. The session owns and disposes it.</param>
    /// <param name="isInitiator">True on the side that started the session; it opens odd-numbered streams.</param>
    public MuxSession(Stream transport, bool isInitiator)
    {
        _transport = transport ?? throw new ArgumentNullException(nameof(transport));
        _isInitiator = isInitiator;
        _nextStreamId = isInitiator ? 1u : 2u;
    }

    /// <summary>Completes with an <see cref="ErrorCodes"/> value when the session has ended, for whatever reason.</summary>
    public Task<string> Completion => _completion.Task;

    public bool IsClosed => _completion.Task.IsCompleted;

    public int OpenStreamCount => _streams.Count;

    public void Start() => _readLoop ??= Task.Run(ReadLoopAsync);

    /// <summary>Opens a new stream. The peer learns of it with the first frame.</summary>
    public async ValueTask<MuxStream> OpenStreamAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfClosed();
        // The number is taken and the opening frame is sent as one step: the peer requires stream
        // numbers to arrive in increasing order, and two streams opened at the same moment must
        // not overtake each other on the way out.
        MuxStream? stream = null;
        try
        {
            await SendFrameAsync(MuxFrameType.WindowUpdate, MuxFlags.Syn, () =>
            {
                uint id = _nextStreamId;
                _nextStreamId += 2;
                stream = new MuxStream(this, id);
                _streams[id] = stream;
                return id;
            }, 0, default, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            if (stream is not null)
            {
                _streams.TryRemove(stream.Id, out _);
            }
            throw;
        }
        return stream!;
    }

    /// <summary>Waits for the peer to open a stream.</summary>
    public async ValueTask<MuxStream> AcceptStreamAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            return await _incoming.Reader.ReadAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (ChannelClosedException)
        {
            throw new IOException($"The session is closed ({CloseReason}).");
        }
    }

    /// <summary>Round trip to the peer inside the encrypted channel; proves the session is alive.</summary>
    public async Task<TimeSpan> PingAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfClosed();
        uint id = Interlocked.Increment(ref _nextPingId);
        var pending = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        _pings[id] = pending;
        long started = System.Diagnostics.Stopwatch.GetTimestamp();
        try
        {
            await SendFrameAsync(MuxFrameType.Ping, MuxFlags.Syn, 0, id, default, cancellationToken).ConfigureAwait(false);
            await pending.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
            return System.Diagnostics.Stopwatch.GetElapsedTime(started);
        }
        finally
        {
            _pings.TryRemove(id, out _);
        }
    }

    internal string CloseReason => _completion.Task.IsCompletedSuccessfully ? _completion.Task.Result : ErrorCodes.SessionClosed;

    internal CancellationToken Closed => _closed.Token;

    internal ValueTask SendFrameAsync(byte type, MuxFlags flags, uint streamId, uint length, ReadOnlyMemory<byte> payload, CancellationToken cancellationToken)
        => SendFrameAsync(type, flags, () => streamId, length, payload, cancellationToken);

    /// <param name="streamId">Called once the frame is next in line to be written, so that a number assigned there reaches the peer in order.</param>
    private async ValueTask SendFrameAsync(byte type, MuxFlags flags, Func<uint> streamId, uint length, ReadOnlyMemory<byte> payload, CancellationToken cancellationToken)
    {
        byte[] frame = ArrayPool<byte>.Shared.Rent(HeaderSize + payload.Length);
        try
        {
            frame[0] = 0; // protocol version
            frame[1] = type;
            BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(2), (ushort)flags);
            BinaryPrimitives.WriteUInt32BigEndian(frame.AsSpan(8), length);
            payload.CopyTo(frame.AsMemory(HeaderSize));

            await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                ThrowIfClosed();
                BinaryPrimitives.WriteUInt32BigEndian(frame.AsSpan(4), streamId());
                // Header and payload go out in one write so they share a TLS record.
                await _transport.WriteAsync(frame.AsMemory(0, HeaderSize + payload.Length), cancellationToken).ConfigureAwait(false);
                await _transport.FlushAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is IOException or ObjectDisposedException or InvalidOperationException)
            {
                Close(ErrorCodes.PathClosed);
                throw new IOException($"The session is closed ({CloseReason}).", ex);
            }
            finally
            {
                _writeLock.Release();
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(frame);
        }
    }

    internal void RemoveStream(uint id) => _streams.TryRemove(id, out _);

    private async Task ReadLoopAsync()
    {
        byte[] header = new byte[HeaderSize];
        byte[] scratch = ArrayPool<byte>.Shared.Rent(MaxFrameData);
        string reason = ErrorCodes.PathClosed;
        try
        {
            CancellationToken closed = _closed.Token;
            while (true)
            {
                if (!await TryReadExactlyAsync(header, closed).ConfigureAwait(false))
                {
                    break;
                }

                byte type = header[1];
                var flags = (MuxFlags)BinaryPrimitives.ReadUInt16BigEndian(header.AsSpan(2));
                uint streamId = BinaryPrimitives.ReadUInt32BigEndian(header.AsSpan(4));
                uint length = BinaryPrimitives.ReadUInt32BigEndian(header.AsSpan(8));
                if (header[0] != 0)
                {
                    reason = ErrorCodes.MuxProtocolError;
                    break;
                }

                bool ok = type switch
                {
                    MuxFrameType.Data => await HandleDataAsync(flags, streamId, length, scratch, closed).ConfigureAwait(false),
                    MuxFrameType.WindowUpdate => await HandleWindowUpdateAsync(flags, streamId, length, closed).ConfigureAwait(false),
                    MuxFrameType.Ping => await HandlePingAsync(flags, length, closed).ConfigureAwait(false),
                    MuxFrameType.GoAway => false,
                    _ => false,
                };
                if (!ok)
                {
                    reason = type == MuxFrameType.GoAway && length == 0 ? ErrorCodes.SessionClosed : ErrorCodes.MuxProtocolError;
                    break;
                }
            }
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException or OperationCanceledException or InvalidOperationException)
        {
            // TLS wraps what the path reports; a path that knows why it ended says so.
            for (Exception? e = ex; e is not null; e = e.InnerException)
            {
                if (e is Transport.PathException path)
                {
                    reason = path.ErrorCode;
                    break;
                }
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(scratch);
            Close(reason);
        }
    }

    private async ValueTask<bool> HandleDataAsync(MuxFlags flags, uint streamId, uint length, byte[] scratch, CancellationToken cancellationToken)
    {
        if (streamId == 0 || length > InitialWindow)
        {
            return false;
        }

        if (!TryResolveStream(flags, streamId, out MuxStream? stream, out bool refused))
        {
            return false;
        }
        if (refused)
        {
            await SendFrameAsync(MuxFrameType.WindowUpdate, MuxFlags.Rst, streamId, 0, default, cancellationToken).ConfigureAwait(false);
        }

        // The payload always has to be consumed, even for a stream that no longer exists.
        uint remaining = length;
        while (remaining > 0)
        {
            int chunk = (int)Math.Min(remaining, (uint)scratch.Length);
            if (!await TryReadExactlyAsync(scratch.AsMemory(0, chunk), cancellationToken).ConfigureAwait(false))
            {
                return false;
            }
            if (stream is not null && !stream.OnData(scratch.AsSpan(0, chunk)))
            {
                return false; // the peer ignored our flow-control window
            }
            remaining -= (uint)chunk;
        }

        stream?.OnFlags(flags);
        return true;
    }

    private async ValueTask<bool> HandleWindowUpdateAsync(MuxFlags flags, uint streamId, uint delta, CancellationToken cancellationToken)
    {
        if (streamId == 0)
        {
            return false;
        }
        if (!TryResolveStream(flags, streamId, out MuxStream? stream, out bool refused))
        {
            return false;
        }
        if (refused)
        {
            await SendFrameAsync(MuxFrameType.WindowUpdate, MuxFlags.Rst, streamId, 0, default, cancellationToken).ConfigureAwait(false);
            return true;
        }

        if (stream is not null)
        {
            stream.OnWindowUpdate(delta);
            stream.OnFlags(flags);
        }
        return true;
    }

    private async ValueTask<bool> HandlePingAsync(MuxFlags flags, uint value, CancellationToken cancellationToken)
    {
        if ((flags & MuxFlags.Syn) != 0)
        {
            await SendFrameAsync(MuxFrameType.Ping, MuxFlags.Ack, 0, value, default, cancellationToken).ConfigureAwait(false);
        }
        else if ((flags & MuxFlags.Ack) != 0 && _pings.TryGetValue(value, out TaskCompletionSource? pending))
        {
            pending.TrySetResult();
        }
        return true;
    }

    /// <summary>
    /// Finds the stream a frame belongs to, creating it for a valid SYN. Returns false on a protocol
    /// violation. A frame for an already closed stream yields a null stream, which is not an error.
    /// </summary>
    private bool TryResolveStream(MuxFlags flags, uint streamId, out MuxStream? stream, out bool refused)
    {
        refused = false;
        if ((flags & MuxFlags.Syn) == 0)
        {
            _streams.TryGetValue(streamId, out stream);
            return true;
        }

        stream = null;
        bool remoteParity = _isInitiator ? streamId % 2 == 0 : streamId % 2 == 1;
        if (!remoteParity || streamId <= _lastRemoteStreamId)
        {
            return false;
        }
        _lastRemoteStreamId = streamId;

        if (_streams.Count >= MaxStreams)
        {
            refused = true;
            return true;
        }

        stream = new MuxStream(this, streamId, openedByPeer: true);
        _streams[streamId] = stream;
        if (!_incoming.Writer.TryWrite(stream))
        {
            _streams.TryRemove(streamId, out _);
            stream = null;
            refused = true;
        }
        return true;
    }

    private async ValueTask<bool> TryReadExactlyAsync(Memory<byte> buffer, CancellationToken cancellationToken)
    {
        int total = 0;
        while (total < buffer.Length)
        {
            int read = await _transport.ReadAsync(buffer[total..], cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                return false;
            }
            total += read;
        }
        return true;
    }

    private void Close(string reason)
    {
        if (!_completion.TrySetResult(reason))
        {
            return;
        }

        _closed.Cancel();
        _incoming.Writer.TryComplete();
        foreach (MuxStream stream in _streams.Values)
        {
            stream.OnSessionClosed(reason);
        }
        _streams.Clear();
        foreach (TaskCompletionSource ping in _pings.Values)
        {
            ping.TrySetException(new IOException($"The session is closed ({reason})."));
        }
    }

    private void ThrowIfClosed()
    {
        if (_completion.Task.IsCompleted)
        {
            throw new IOException($"The session is closed ({CloseReason}).");
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        if (!_completion.Task.IsCompleted)
        {
            try
            {
                using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
                await SendFrameAsync(MuxFrameType.GoAway, MuxFlags.None, 0, 0, default, timeout.Token).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is IOException or OperationCanceledException or ObjectDisposedException)
            {
            }
        }

        Close(ErrorCodes.SessionClosed);
        try
        {
            await _transport.DisposeAsync().ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException or InvalidOperationException)
        {
        }

        if (_readLoop is { } loop)
        {
            try
            {
                await loop.ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
            }
        }
        _closed.Dispose();
    }
}

internal static class MuxFrameType
{
    public const byte Data = 0;
    public const byte WindowUpdate = 1;
    public const byte Ping = 2;
    public const byte GoAway = 3;
}

[Flags]
internal enum MuxFlags : ushort
{
    None = 0,
    Syn = 1,
    Ack = 2,
    Fin = 4,
    Rst = 8,
}
