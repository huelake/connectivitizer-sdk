using System.Buffers;
using System.IO.Pipelines;

namespace Huelake.Connectivitizer.Client.Mux;

/// <summary>One bidirectional byte stream inside a <see cref="MuxSession"/>.</summary>
public sealed class MuxStream : Stream
{
    private readonly MuxSession _session;
    private readonly Pipe _inbound = new(new PipeOptions(pauseWriterThreshold: 0, resumeWriterThreshold: 0, useSynchronizationContext: false));
    private readonly SemaphoreSlim _writeGate = new(1, 1);
    private readonly SemaphoreSlim _windowSignal = new(0);
    private readonly Lock _state = new();
    private readonly Lock _inboundWrite = new();
    private bool _inboundCompleted;
    private long _sendWindow = MuxSession.InitialWindow;
    private long _receiveWindow = MuxSession.InitialWindow;
    private long _consumedSinceUpdate;
    private bool _localFin;
    private bool _remoteFin;
    private bool _reset;
    private bool _needsAck;
    private string? _closedReason;
    private int _disposed;

    internal MuxStream(MuxSession session, uint id, bool openedByPeer = false)
    {
        _session = session;
        Id = id;
        _needsAck = openedByPeer;
    }

    public uint Id { get; }

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

        ReadResult result;
        try
        {
            result = await _inbound.Reader.ReadAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (InvalidOperationException ex)
        {
            throw new IOException("The stream is closed.", ex);
        }

        ReadOnlySequence<byte> available = result.Buffer;
        int count = (int)Math.Min(available.Length, buffer.Length);
        available.Slice(0, count).CopyTo(buffer.Span);
        _inbound.Reader.AdvanceTo(available.GetPosition(count));

        if (count == 0 && result.IsCompleted)
        {
            string? closedReason;
            lock (_state)
            {
                closedReason = _remoteFin ? null : _closedReason;
            }
            if (closedReason is not null)
            {
                // Nothing is left of what arrived before the session ended, and the peer never finished this stream.
                throw new IOException($"The session is closed ({closedReason}).");
            }
        }

        if (count > 0)
        {
            await GrantReceiveWindowAsync(count, cancellationToken).ConfigureAwait(false);
        }
        return count;
    }

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        await _writeGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            while (!buffer.IsEmpty)
            {
                int chunk = await ReserveSendWindowAsync(Math.Min(buffer.Length, MuxSession.MaxFrameData), cancellationToken).ConfigureAwait(false);
                await _session.SendFrameAsync(MuxFrameType.Data, TakeAckFlag(), Id, (uint)chunk, buffer[..chunk], cancellationToken).ConfigureAwait(false);
                buffer = buffer[chunk..];
            }
        }
        finally
        {
            _writeGate.Release();
        }
    }

    /// <summary>
    /// Signals that this side will send nothing more, while still reading what the peer sends
    /// (a TCP-style half close).
    /// </summary>
    public async ValueTask CompleteWritesAsync(CancellationToken cancellationToken = default)
    {
        lock (_state)
        {
            if (_localFin || _reset || _closedReason is not null)
            {
                return;
            }
            _localFin = true;
        }

        await _session.SendFrameAsync(MuxFrameType.WindowUpdate, MuxFlags.Fin | TakeAckFlag(), Id, 0, default, cancellationToken).ConfigureAwait(false);
        RemoveIfFinished();
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override int Read(byte[] buffer, int offset, int count) => ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

    public override void Write(byte[] buffer, int offset, int count) => WriteAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

    public override void Flush()
    {
    }

    public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    internal bool OnData(ReadOnlySpan<byte> data)
    {
        lock (_state)
        {
            if (_remoteFin || _reset)
            {
                return true; // late data for a finished stream is dropped, not an error
            }
            if (data.Length > _receiveWindow)
            {
                return false;
            }
            _receiveWindow -= data.Length;
        }

        if (Volatile.Read(ref _disposed) != 0)
        {
            return true;
        }

        lock (_inboundWrite)
        {
            if (_inboundCompleted)
            {
                return true;
            }
            Span<byte> target = _inbound.Writer.GetSpan(data.Length);
            data.CopyTo(target);
            _inbound.Writer.Advance(data.Length);
            // No back-pressure from the pipe (thresholds are 0): the mux window is the flow control.
            _ = _inbound.Writer.FlushAsync();
        }
        return true;
    }

    internal void OnWindowUpdate(uint delta)
    {
        if (delta == 0)
        {
            return;
        }
        Interlocked.Add(ref _sendWindow, delta);
        _windowSignal.Release();
    }

    internal void OnFlags(MuxFlags flags)
    {
        if ((flags & MuxFlags.Rst) != 0)
        {
            lock (_state)
            {
                _reset = true;
            }
            CompleteInbound(new IOException("The stream was reset by the peer."));
            _windowSignal.Release();
            _session.RemoveStream(Id);
            return;
        }

        if ((flags & MuxFlags.Fin) != 0)
        {
            lock (_state)
            {
                _remoteFin = true;
            }
            CompleteInbound(null);
            RemoveIfFinished();
        }
    }

    internal void OnSessionClosed(string reason)
    {
        lock (_state)
        {
            _closedReason = reason;
        }
        // What arrived before the session ended can still be read - the peer's last words on the
        // control stream say why it ended. Reading past that fails (see ReadAsync).
        CompleteInbound(null);
        _windowSignal.Release();
    }

    private async ValueTask<int> ReserveSendWindowAsync(int wanted, CancellationToken cancellationToken)
    {
        while (true)
        {
            lock (_state)
            {
                if (_reset)
                {
                    throw new IOException("The stream was reset by the peer.");
                }
                if (_closedReason is not null)
                {
                    throw new IOException($"The session is closed ({_closedReason}).");
                }
                if (_localFin || Volatile.Read(ref _disposed) != 0)
                {
                    throw new IOException("The stream is closed for writing.");
                }
            }

            long window = Interlocked.Read(ref _sendWindow);
            if (window > 0)
            {
                int granted = (int)Math.Min(window, wanted);
                if (Interlocked.CompareExchange(ref _sendWindow, window - granted, window) == window)
                {
                    return granted;
                }
                continue;
            }

            await _windowSignal.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    private async ValueTask GrantReceiveWindowAsync(int consumed, CancellationToken cancellationToken)
    {
        long delta;
        lock (_state)
        {
            _consumedSinceUpdate += consumed;
            if (_consumedSinceUpdate < MuxSession.InitialWindow / 2 || _remoteFin || _reset || _closedReason is not null)
            {
                return;
            }
            delta = _consumedSinceUpdate;
            _consumedSinceUpdate = 0;
            _receiveWindow += delta;
        }

        try
        {
            await _session.SendFrameAsync(MuxFrameType.WindowUpdate, TakeAckFlag(), Id, (uint)delta, default, cancellationToken).ConfigureAwait(false);
        }
        catch (IOException)
        {
            // The session ended while we were reading buffered data; the read itself is still valid.
        }
    }

    /// <summary>The read loop writes into the pipe while other threads may end the stream, so both are serialised.</summary>
    private void CompleteInbound(Exception? error)
    {
        lock (_inboundWrite)
        {
            if (_inboundCompleted)
            {
                return;
            }
            _inboundCompleted = true;
            _inbound.Writer.Complete(error);
        }
    }

    private MuxFlags TakeAckFlag()
    {
        lock (_state)
        {
            if (!_needsAck)
            {
                return MuxFlags.None;
            }
            _needsAck = false;
            return MuxFlags.Ack;
        }
    }

    private void RemoveIfFinished()
    {
        bool finished;
        lock (_state)
        {
            finished = _localFin && _remoteFin;
        }
        if (finished)
        {
            _session.RemoveStream(Id);
        }
    }

    public override async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        bool sendReset;
        bool sendFin;
        lock (_state)
        {
            bool alive = !_reset && _closedReason is null;
            // Still receiving: the peer must learn we are gone, or it would wait for window forever.
            sendReset = alive && !_remoteFin;
            sendFin = alive && _remoteFin && !_localFin;
            _localFin = true;
        }

        try
        {
            if (sendReset)
            {
                await _session.SendFrameAsync(MuxFrameType.WindowUpdate, MuxFlags.Rst, Id, 0, default, CancellationToken.None).ConfigureAwait(false);
            }
            else if (sendFin)
            {
                await _session.SendFrameAsync(MuxFrameType.WindowUpdate, MuxFlags.Fin | TakeAckFlag(), Id, 0, default, CancellationToken.None).ConfigureAwait(false);
            }
        }
        catch (IOException)
        {
        }

        _session.RemoveStream(Id);
        CompleteInbound(null);
        _inbound.Reader.Complete();
        _windowSignal.Release();
        await base.DisposeAsync().ConfigureAwait(false);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing && Volatile.Read(ref _disposed) == 0)
        {
            DisposeAsync().AsTask().GetAwaiter().GetResult();
        }
        base.Dispose(disposing);
    }
}
