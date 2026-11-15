using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Huelake.Connectivitizer.Protocol;

namespace Huelake.Connectivitizer.Client.Security;

/// <summary>
/// The end-to-end layer for endpoints that share a key instead of certificates (protocol
/// section 4a): the Noise handshake <c>NNpsk0</c> with X25519, ChaCha20-Poly1305 and SHA-256, run
/// over whatever byte stream the path provides. Each session uses fresh key-agreement keys, so
/// recorded traffic stays unreadable even if the shared key leaks later; the shared key is what
/// authenticates the two ends to each other. Nothing between them holds it.
/// </summary>
public static class SharedKeyChannel
{
    /// <summary>Largest number of plaintext bytes in one message, so an endpoint with little memory needs only small buffers.</summary>
    public const int MaxPlaintext = 4096;

    internal const int TagSize = 16;
    private const int HandshakeMessageSize = X25519.KeySize + TagSize;

    /// <summary>
    /// What both handshakes are bound to: this protocol, this session and this grant. Two ends that
    /// disagree about any of them derive different keys and never get a channel.
    /// </summary>
    public static byte[] Prologue(string sessionId, string grantHashHex) => Encoding.ASCII.GetBytes($"cz-e2e-shared-key/1|{sessionId}|{grantHashHex}");

    /// <summary>Runs the handshake as the initiating endpoint.</summary>
    public static async Task<SecureStream> ConnectAsync(Stream path, SharedKey key, byte[] prologue, string peerLabel, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(path);
        ArgumentNullException.ThrowIfNull(key);
        EnsureSupported();
        try
        {
            NoiseHandshake handshake = NoiseHandshake.StartInitiator(prologue, key.Bytes, RandomNumberGenerator.GetBytes(X25519.KeySize));
            await WriteFrameAsync(path, handshake.WriteFirst([]), cancellationToken).ConfigureAwait(false);

            byte[]? second = await ReadFrameAsync(path, HandshakeMessageSize, cancellationToken).ConfigureAwait(false);
            if (second is { Length: 0 })
            {
                // The device answers with an empty message when none of its keys fits.
                throw new SecureChannelException(ErrorCodes.E2eSharedKeyMismatch, "The device does not hold this shared key.");
            }
            if (second is not { Length: HandshakeMessageSize })
            {
                throw new SecureChannelException(ErrorCodes.E2eHandshakeFailed, "The peer ended the end-to-end handshake.");
            }
            if (!handshake.ReadSecond(second, out _))
            {
                throw new SecureChannelException(ErrorCodes.E2eSharedKeyMismatch, "The device answered with a different shared key.");
            }

            (byte[] sendKey, byte[] receiveKey) = handshake.Split();
            return new SecureStream(new NoiseStream(path, sendKey, receiveKey), PeerOf(key, peerLabel));
        }
        catch (IOException ex)
        {
            await path.DisposeAsync().ConfigureAwait(false);
            throw new SecureChannelException(ErrorCodes.E2eHandshakeFailed, "The path ended during the end-to-end handshake.", ex);
        }
        catch
        {
            await path.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    /// <summary>
    /// Runs the handshake as the accepting endpoint. It may hold several keys (one per peer it
    /// shares one with); the one the initiator used is found by trying them.
    /// </summary>
    public static async Task<SecureStream> AcceptAsync(Stream path, IReadOnlyList<SharedKey> keys, byte[] prologue, string peerLabel, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(path);
        ArgumentNullException.ThrowIfNull(keys);
        EnsureSupported();
        try
        {
            byte[]? first = await ReadFrameAsync(path, HandshakeMessageSize, cancellationToken).ConfigureAwait(false);
            if (first is not { Length: HandshakeMessageSize })
            {
                throw new SecureChannelException(ErrorCodes.E2eHandshakeFailed, "The peer ended the end-to-end handshake.");
            }

            NoiseHandshake? handshake = null;
            SharedKey? used = null;
            foreach (SharedKey key in keys)
            {
                handshake = NoiseHandshake.TryStartResponder(prologue, key.Bytes, first, out _);
                if (handshake is not null)
                {
                    used = key;
                    break;
                }
            }
            if (handshake is null || used is null)
            {
                await WriteFrameAsync(path, ReadOnlyMemory<byte>.Empty, cancellationToken).ConfigureAwait(false);
                throw new SecureChannelException(ErrorCodes.E2eSharedKeyMismatch, "The initiator used a shared key this endpoint does not hold.");
            }

            await WriteFrameAsync(path, handshake.WriteSecond(RandomNumberGenerator.GetBytes(X25519.KeySize), []), cancellationToken).ConfigureAwait(false);
            (byte[] initiatorKey, byte[] responderKey) = handshake.Split();
            return new SecureStream(new NoiseStream(path, sendKey: responderKey, receiveKey: initiatorKey), PeerOf(used, peerLabel));
        }
        catch (IOException ex)
        {
            await path.DisposeAsync().ConfigureAwait(false);
            throw new SecureChannelException(ErrorCodes.E2eHandshakeFailed, "The path ended during the end-to-end handshake.", ex);
        }
        catch
        {
            await path.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    /// <summary>
    /// A peer proven to hold the key. Which holder it is the key cannot tell: the name shown is
    /// the one the platform gave, a label and nothing more.
    /// </summary>
    private static PeerIdentity PeerOf(SharedKey key, string peerLabel) => new(key.AllowListEntry, peerLabel, TrustLevel.SharedKey, string.Empty);

    private static void EnsureSupported()
    {
        if (!ChaCha20Poly1305.IsSupported)
        {
            throw new PlatformNotSupportedException("Shared-key sessions need ChaCha20-Poly1305, which this operating system does not provide (Windows 11 / Server 2022, or OpenSSL 1.1 and later).");
        }
    }

    private static async Task WriteFrameAsync(Stream path, ReadOnlyMemory<byte> message, CancellationToken cancellationToken)
    {
        byte[] frame = new byte[2 + message.Length];
        BinaryPrimitives.WriteUInt16BigEndian(frame, (ushort)message.Length);
        message.CopyTo(frame.AsMemory(2));
        await path.WriteAsync(frame, cancellationToken).ConfigureAwait(false);
        await path.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Reads one length-prefixed message; null at the end of the stream.</summary>
    private static async Task<byte[]?> ReadFrameAsync(Stream path, int maxLength, CancellationToken cancellationToken)
    {
        byte[] header = new byte[2];
        if (await path.ReadAtLeastAsync(header, 2, throwOnEndOfStream: false, cancellationToken).ConfigureAwait(false) < 2)
        {
            return null;
        }
        int length = BinaryPrimitives.ReadUInt16BigEndian(header);
        if (length > maxLength)
        {
            throw new SecureChannelException(ErrorCodes.E2eHandshakeFailed, "The peer sent a message that is too long for this protocol.");
        }
        byte[] message = new byte[length];
        if (length > 0 && await path.ReadAtLeastAsync(message, length, throwOnEndOfStream: false, cancellationToken).ConfigureAwait(false) < length)
        {
            return null;
        }
        return message;
    }

    /// <summary>ChaCha20-Poly1305 with the nonce Noise prescribes: four zero bytes, then the counter, little-endian.</summary>
    internal static void WriteNonce(Span<byte> nonce, ulong counter)
    {
        nonce.Clear();
        BinaryPrimitives.WriteUInt64LittleEndian(nonce[4..], counter);
    }

    /// <summary>The encrypted byte stream after the handshake: length-prefixed messages of at most <see cref="MaxPlaintext"/> bytes.</summary>
    private sealed class NoiseStream(Stream inner, byte[] sendKey, byte[] receiveKey) : Stream
    {
        private readonly ChaCha20Poly1305 _send = new(sendKey);
        private readonly ChaCha20Poly1305 _receive = new(receiveKey);
        private readonly byte[] _header = new byte[2];
        private readonly byte[] _ciphertext = new byte[MaxPlaintext + TagSize];
        private readonly byte[] _plaintext = new byte[MaxPlaintext];
        private readonly byte[] _outgoing = new byte[2 + MaxPlaintext + TagSize];
        private ulong _sendNonce;
        private ulong _receiveNonce;
        private int _available;
        private int _offset;
        private bool _ended;

        public override bool CanRead => true;
        public override bool CanWrite => true;
        public override bool CanSeek => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            while (_available == 0)
            {
                if (_ended || buffer.Length == 0)
                {
                    return 0;
                }
                if (await inner.ReadAtLeastAsync(_header, 2, throwOnEndOfStream: false, cancellationToken).ConfigureAwait(false) < 2)
                {
                    _ended = true;
                    return 0;
                }
                int length = BinaryPrimitives.ReadUInt16BigEndian(_header);
                if (length < TagSize || length > _ciphertext.Length)
                {
                    throw new IOException("The peer sent a malformed encrypted message.");
                }
                if (await inner.ReadAtLeastAsync(_ciphertext.AsMemory(0, length), length, throwOnEndOfStream: false, cancellationToken).ConfigureAwait(false) < length)
                {
                    // Cut off inside a message: the path broke, this is not an orderly end.
                    throw new IOException("The path ended inside an encrypted message.");
                }
                Decrypt(length);
            }

            int count = Math.Min(buffer.Length, _available);
            _plaintext.AsSpan(_offset, count).CopyTo(buffer.Span);
            _offset += count;
            _available -= count;
            return count;
        }

        private void Decrypt(int length)
        {
            Span<byte> nonce = stackalloc byte[12];
            WriteNonce(nonce, _receiveNonce++);
            int size = length - TagSize;
            try
            {
                _receive.Decrypt(nonce, _ciphertext.AsSpan(0, size), _ciphertext.AsSpan(size, TagSize), _plaintext.AsSpan(0, size));
            }
            catch (AuthenticationTagMismatchException ex)
            {
                throw new IOException("An encrypted message was altered on the way.", ex);
            }
            _offset = 0;
            _available = size;
        }

        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            while (buffer.Length > 0)
            {
                int size = Math.Min(buffer.Length, MaxPlaintext);
                Encrypt(buffer.Span[..size]);
                await inner.WriteAsync(_outgoing.AsMemory(0, 2 + size + TagSize), cancellationToken).ConfigureAwait(false);
                buffer = buffer[size..];
            }
        }

        private void Encrypt(ReadOnlySpan<byte> plaintext)
        {
            Span<byte> nonce = stackalloc byte[12];
            WriteNonce(nonce, _sendNonce++);
            BinaryPrimitives.WriteUInt16BigEndian(_outgoing, (ushort)(plaintext.Length + TagSize));
            _send.Encrypt(nonce, plaintext, _outgoing.AsSpan(2, plaintext.Length), _outgoing.AsSpan(2 + plaintext.Length, TagSize));
        }

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

        public override int Read(byte[] buffer, int offset, int count) => ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

        public override void Write(byte[] buffer, int offset, int count) => WriteAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

        public override Task FlushAsync(CancellationToken cancellationToken) => inner.FlushAsync(cancellationToken);

        public override void Flush() => inner.Flush();

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _send.Dispose();
                _receive.Dispose();
                inner.Dispose();
            }
            base.Dispose(disposing);
        }

        public override async ValueTask DisposeAsync()
        {
            _send.Dispose();
            _receive.Dispose();
            await inner.DisposeAsync().ConfigureAwait(false);
            GC.SuppressFinalize(this);
        }
    }
}

/// <summary>
/// The handshake <c>Noise_NNpsk0_25519_ChaChaPoly_SHA256</c> as the Noise specification (revision 34)
/// defines it: the pre-shared key is mixed in first, then each side sends a fresh X25519 key.
/// <code>
///   -> psk, e
///   &lt;- e, ee
/// </code>
/// Kept apart from the stream handling so that it can be checked against published test vectors.
/// </summary>
internal sealed class NoiseHandshake
{
    private const int TagSize = SharedKeyChannel.TagSize;
    private static readonly byte[] ProtocolName = Encoding.ASCII.GetBytes("Noise_NNpsk0_25519_ChaChaPoly_SHA256");

    private byte[] _chainingKey;
    private byte[] _hash;
    private byte[]? _key;
    private ulong _nonce;
    private byte[]? _ephemeral;
    private byte[]? _remotePublic;

    private NoiseHandshake(ReadOnlySpan<byte> prologue, ReadOnlySpan<byte> sharedKey)
    {
        // The protocol name is longer than a hash, so the initial hash is the hash of the name.
        _hash = SHA256.HashData(ProtocolName);
        _chainingKey = (byte[])_hash.Clone();
        MixHash(prologue);
        MixKeyAndHash(sharedKey);
    }

    /// <summary>The initiator's side. <paramref name="ephemeralPrivate"/> must be 32 fresh random bytes.</summary>
    public static NoiseHandshake StartInitiator(ReadOnlySpan<byte> prologue, ReadOnlySpan<byte> sharedKey, byte[] ephemeralPrivate)
        => new(prologue, sharedKey) { _ephemeral = ephemeralPrivate };

    /// <summary>The initiator's message: its ephemeral public key and the encrypted payload.</summary>
    public byte[] WriteFirst(ReadOnlySpan<byte> payload)
    {
        byte[] ephemeralPublic = X25519.PublicKey(_ephemeral!);
        MixHash(ephemeralPublic);
        MixKey(ephemeralPublic);
        byte[] message = new byte[X25519.KeySize + payload.Length + TagSize];
        ephemeralPublic.CopyTo(message, 0);
        EncryptAndHash(payload, message.AsSpan(X25519.KeySize));
        return message;
    }

    /// <summary>Processes the responder's message. False when it was not made with the same shared key.</summary>
    public bool ReadSecond(ReadOnlySpan<byte> message, out byte[] payload)
    {
        payload = [];
        if (message.Length < X25519.KeySize + TagSize)
        {
            return false;
        }
        ReadOnlySpan<byte> remotePublic = message[..X25519.KeySize];
        MixHash(remotePublic);
        MixKey(remotePublic);
        MixKey(Agree(_ephemeral!, remotePublic));
        CryptographicOperations.ZeroMemory(_ephemeral);
        payload = new byte[message.Length - X25519.KeySize - TagSize];
        return DecryptAndHash(message[X25519.KeySize..], payload);
    }

    /// <summary>
    /// The responder's side: processes the initiator's message with one candidate key. Null when
    /// the message was not made with that key.
    /// </summary>
    public static NoiseHandshake? TryStartResponder(ReadOnlySpan<byte> prologue, ReadOnlySpan<byte> sharedKey, ReadOnlySpan<byte> firstMessage, out byte[] payload)
    {
        payload = [];
        if (firstMessage.Length < X25519.KeySize + TagSize)
        {
            return null;
        }
        var handshake = new NoiseHandshake(prologue, sharedKey);
        ReadOnlySpan<byte> remotePublic = firstMessage[..X25519.KeySize];
        handshake.MixHash(remotePublic);
        handshake.MixKey(remotePublic);
        payload = new byte[firstMessage.Length - X25519.KeySize - TagSize];
        if (!handshake.DecryptAndHash(firstMessage[X25519.KeySize..], payload))
        {
            return null;
        }
        handshake._remotePublic = remotePublic.ToArray();
        return handshake;
    }

    /// <summary>The responder's message. <paramref name="ephemeralPrivate"/> must be 32 fresh random bytes.</summary>
    public byte[] WriteSecond(byte[] ephemeralPrivate, ReadOnlySpan<byte> payload)
    {
        byte[] ephemeralPublic = X25519.PublicKey(ephemeralPrivate);
        MixHash(ephemeralPublic);
        MixKey(ephemeralPublic);
        MixKey(Agree(ephemeralPrivate, _remotePublic!));
        CryptographicOperations.ZeroMemory(ephemeralPrivate);
        byte[] message = new byte[X25519.KeySize + payload.Length + TagSize];
        ephemeralPublic.CopyTo(message, 0);
        EncryptAndHash(payload, message.AsSpan(X25519.KeySize));
        return message;
    }

    /// <summary>The hash over everything both sides sent and mixed in. Equal on both ends exactly when the handshake agreed.</summary>
    public byte[] HandshakeHash => (byte[])_hash.Clone();

    /// <summary>The two transport keys: the first protects what the initiator sends, the second what the responder sends.</summary>
    public (byte[] Initiator, byte[] Responder) Split()
    {
        byte[] temp = Hmac(_chainingKey, default);
        byte[] first = Expand(temp, default, 1);
        byte[] second = Expand(temp, first, 2);
        return (first, second);
    }

    private static byte[] Agree(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> remotePublic)
    {
        byte[] shared = X25519.ScalarMult(privateKey, remotePublic);
        // A peer that sends a point of small order forces a known result; such a handshake is refused.
        if (CryptographicOperations.FixedTimeEquals(shared, new byte[X25519.KeySize]))
        {
            throw new SecureChannelException(ErrorCodes.E2eHandshakeFailed, "The peer sent an invalid key-agreement value.");
        }
        return shared;
    }

    private void MixHash(ReadOnlySpan<byte> data)
    {
        byte[] input = new byte[_hash.Length + data.Length];
        _hash.CopyTo(input, 0);
        data.CopyTo(input.AsSpan(_hash.Length));
        _hash = SHA256.HashData(input);
    }

    private void MixKey(ReadOnlySpan<byte> inputKeyMaterial)
    {
        byte[] temp = Hmac(_chainingKey, inputKeyMaterial);
        byte[] first = Expand(temp, default, 1);
        byte[] second = Expand(temp, first, 2);
        _chainingKey = first;
        SetKey(second);
    }

    private void MixKeyAndHash(ReadOnlySpan<byte> inputKeyMaterial)
    {
        byte[] temp = Hmac(_chainingKey, inputKeyMaterial);
        byte[] first = Expand(temp, default, 1);
        byte[] second = Expand(temp, first, 2);
        byte[] third = Expand(temp, second, 3);
        _chainingKey = first;
        MixHash(second);
        SetKey(third);
    }

    /// <summary>Writes ciphertext and tag for <paramref name="plaintext"/> into <paramref name="output"/> and mixes them into the hash.</summary>
    private void EncryptAndHash(ReadOnlySpan<byte> plaintext, Span<byte> output)
    {
        Span<byte> nonce = stackalloc byte[12];
        SharedKeyChannel.WriteNonce(nonce, _nonce++);
        using var cipher = new ChaCha20Poly1305(_key!);
        cipher.Encrypt(nonce, plaintext, output[..plaintext.Length], output.Slice(plaintext.Length, TagSize), _hash);
        MixHash(output[..(plaintext.Length + TagSize)]);
    }

    private bool DecryptAndHash(ReadOnlySpan<byte> ciphertext, Span<byte> plaintext)
    {
        Span<byte> nonce = stackalloc byte[12];
        SharedKeyChannel.WriteNonce(nonce, _nonce++);
        using var cipher = new ChaCha20Poly1305(_key!);
        try
        {
            cipher.Decrypt(nonce, ciphertext[..^TagSize], ciphertext[^TagSize..], plaintext, _hash);
        }
        catch (AuthenticationTagMismatchException)
        {
            return false;
        }
        MixHash(ciphertext);
        return true;
    }

    private void SetKey(byte[] key)
    {
        _key = key;
        _nonce = 0;
    }

    private static byte[] Hmac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data)
    {
        byte[] output = new byte[32];
        HMACSHA256.HashData(key, data, output);
        return output;
    }

    /// <summary>One output block of the HKDF that Noise defines: HMAC(key, previous block || counter).</summary>
    private static byte[] Expand(ReadOnlySpan<byte> key, ReadOnlySpan<byte> previous, byte counter)
    {
        Span<byte> input = stackalloc byte[previous.Length + 1];
        previous.CopyTo(input);
        input[^1] = counter;
        return Hmac(key, input);
    }
}
