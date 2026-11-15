using System.Collections.Concurrent;
using System.Net.WebSockets;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using Huelake.Connectivitizer.Protocol;

namespace Huelake.Connectivitizer.Client.Platform;

/// <summary>
/// One connection to the signaling channel of the control plane. Carries presence, connection
/// requests and revocations - never application data.
/// </summary>
internal sealed class SignalingClient : IAsyncDisposable
{
    private const int MaxMessageBytes = 64 * 1024;

    private readonly ClientWebSocket _socket = new();
    private readonly SemaphoreSlim _sendLock = new(1, 1);
    private readonly ConcurrentDictionary<string, TaskCompletionSource<SignalEnvelope>> _pending = new(StringComparer.Ordinal);
    private readonly CancellationTokenSource _stop = new();
    private readonly TaskCompletionSource<string> _closed = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private Task? _receiveLoop;
    private long _nextId;
    private int _disposed;

    /// <summary>Called for every message that is not the reply to a request made through <see cref="RequestAsync{TRequest}"/>.</summary>
    public Func<SignalEnvelope, Task>? OnMessage { get; set; }

    /// <summary>Completes with an error code when the connection has ended.</summary>
    public Task<string> Closed => _closed.Task;

    public SignalWelcome? Welcome { get; private set; }

    /// <summary>Connects, authenticates with the machine token and exchanges hello/welcome.</summary>
    public async Task ConnectAsync(Uri signalUrl, string accessToken, SignalHello hello, CancellationToken cancellationToken, string? gatewaySecret = null)
    {
        _socket.Options.SetRequestHeader("Authorization", "Bearer " + accessToken);
        if (gatewaySecret is not null)
        {
            _socket.Options.SetRequestHeader(SignalingHeaders.GatewaySecret, gatewaySecret);
        }
        _socket.Options.KeepAliveInterval = TimeSpan.FromSeconds(25);
        try
        {
            await _socket.ConnectAsync(signalUrl, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is WebSocketException or IOException or HttpRequestException)
        {
            throw new PlatformException(ErrorCodes.SignalingUnavailable, $"The signaling channel at {signalUrl} could not be reached.", ex);
        }

        _receiveLoop = Task.Run(ReceiveLoopAsync);
        SignalEnvelope reply = await RequestAsync(SignalTypes.Hello, hello, ProtocolJsonContext.Default.SignalHello, TimeSpan.FromSeconds(15), cancellationToken).ConfigureAwait(false);
        Welcome = Read(reply, SignalTypes.Welcome, ProtocolJsonContext.Default.SignalWelcome);
    }

    /// <summary>Sends a message and waits for the message that answers it. An <c>error</c> answer is thrown.</summary>
    public async Task<SignalEnvelope> RequestAsync<TRequest>(string type, TRequest data, JsonTypeInfo<TRequest> typeInfo, TimeSpan timeout, CancellationToken cancellationToken)
    {
        string id = Interlocked.Increment(ref _nextId).ToString();
        var pending = new TaskCompletionSource<SignalEnvelope>(TaskCreationOptions.RunContinuationsAsynchronously);
        _pending[id] = pending;
        try
        {
            // A request made while the platform is closing the channel fails with the reason it gives
            // (a revoked credential, say), not as if the platform could not be reached.
            if (_closed.Task.IsCompleted)
            {
                throw ClosedException(_closed.Task.Result);
            }
            try
            {
                await SendAsync(type, data, typeInfo, id, cancellationToken).ConfigureAwait(false);
            }
            catch (PlatformException) when (_closed.Task.IsCompleted)
            {
                throw ClosedException(_closed.Task.Result);
            }
            SignalEnvelope reply;
            try
            {
                reply = await pending.Task.WaitAsync(timeout, cancellationToken).ConfigureAwait(false);
            }
            catch (TimeoutException)
            {
                throw new PlatformException(ErrorCodes.SignalingTimeout, $"The control plane did not answer '{type}' in time.");
            }

            if (reply.Type == SignalTypes.Error)
            {
                SignalError? error = reply.Data?.Deserialize(ProtocolJsonContext.Default.SignalError);
                string code = error?.Code ?? ErrorCodes.InvalidRequest;
                throw new PlatformException(code, error?.Message ?? $"The control plane refused '{type}' ({code}).");
            }
            return reply;
        }
        finally
        {
            _pending.TryRemove(id, out _);
        }
    }

    public async Task SendAsync<T>(string type, T data, JsonTypeInfo<T> typeInfo, string? id = null, CancellationToken cancellationToken = default)
    {
        var envelope = new SignalEnvelope { Type = type, Id = id, Data = JsonSerializer.SerializeToElement(data, typeInfo) };
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(envelope, ProtocolJsonContext.Default.SignalEnvelope);
        await _sendLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await _socket.SendAsync(bytes, WebSocketMessageType.Text, endOfMessage: true, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is WebSocketException or ObjectDisposedException or InvalidOperationException)
        {
            throw new PlatformException(ErrorCodes.SignalingUnavailable, "The signaling channel is closed.", ex);
        }
        finally
        {
            _sendLock.Release();
        }
    }

    private static PlatformException ClosedException(string reason)
        => new(reason, reason == ErrorCodes.SignalingUnavailable ? "The signaling channel closed." : $"The control plane closed the signaling channel ({reason}).");

    public static T Read<T>(SignalEnvelope envelope, string expectedType, JsonTypeInfo<T> typeInfo) where T : class
        => envelope.Type == expectedType && envelope.Data?.Deserialize(typeInfo) is { } value
            ? value
            : throw new PlatformException(ErrorCodes.InvalidRequest, $"Expected '{expectedType}' but received '{envelope.Type}'.");

    private async Task ReceiveLoopAsync()
    {
        byte[] buffer = new byte[MaxMessageBytes];
        string reason = ErrorCodes.SignalingUnavailable;
        try
        {
            while (!_stop.IsCancellationRequested)
            {
                int length = 0;
                ValueWebSocketReceiveResult result;
                do
                {
                    result = await _socket.ReceiveAsync(buffer.AsMemory(length), _stop.Token).ConfigureAwait(false);
                    length += result.Count;
                }
                while (!result.EndOfMessage && length < buffer.Length);

                if (result.MessageType == WebSocketMessageType.Close)
                {
                    // The control plane names its reason (for example a revoked device) in the close frame.
                    reason = _socket.CloseStatusDescription is { Length: > 0 } described ? described : ErrorCodes.SignalingUnavailable;
                    break;
                }

                SignalEnvelope? envelope;
                try
                {
                    envelope = JsonSerializer.Deserialize(buffer.AsSpan(0, length), ProtocolJsonContext.Default.SignalEnvelope);
                }
                catch (JsonException)
                {
                    continue;
                }
                if (envelope is null)
                {
                    continue;
                }

                if (envelope.ReplyTo is { } replyTo && _pending.TryGetValue(replyTo, out TaskCompletionSource<SignalEnvelope>? waiter))
                {
                    waiter.TrySetResult(envelope);
                }
                else if (OnMessage is { } handler)
                {
                    // Handlers run on their own so that a slow one cannot stall the channel.
                    _ = Task.Run(() => handler(envelope));
                }
            }
        }
        catch (Exception ex) when (ex is WebSocketException or OperationCanceledException or IOException or ObjectDisposedException)
        {
        }
        finally
        {
            _closed.TrySetResult(reason);
            foreach (TaskCompletionSource<SignalEnvelope> waiter in _pending.Values)
            {
                waiter.TrySetException(ClosedException(reason));
            }
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }
        if (_socket.State == WebSocketState.Open)
        {
            try
            {
                using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
                await _sendLock.WaitAsync(timeout.Token).ConfigureAwait(false);
                try
                {
                    await _socket.CloseOutputAsync(WebSocketCloseStatus.NormalClosure, null, timeout.Token).ConfigureAwait(false);
                }
                finally
                {
                    _sendLock.Release();
                }
            }
            catch (Exception ex) when (ex is OperationCanceledException or WebSocketException or ObjectDisposedException or IOException)
            {
            }
        }

        await _stop.CancelAsync().ConfigureAwait(false);
        if (_receiveLoop is { } loop)
        {
            try
            {
                await loop.WaitAsync(TimeSpan.FromSeconds(3)).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
            }
        }
        _socket.Dispose();
        _stop.Dispose();
        _closed.TrySetResult(ErrorCodes.SessionClosed);
    }
}
