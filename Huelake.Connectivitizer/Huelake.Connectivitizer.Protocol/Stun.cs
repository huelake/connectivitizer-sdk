using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;

namespace Huelake.Connectivitizer.Protocol;

/// <summary>
/// The small part of STUN (RFC 8489) the protocol uses: a Binding request and its success
/// response carrying XOR-MAPPED-ADDRESS. It lets an endpoint behind NAT learn which public
/// address and port its datagrams appear to come from.
/// </summary>
public static class Stun
{
    public const int HeaderSize = 20;
    public const int TransactionIdSize = 12;
    private const uint MagicCookie = 0x2112A442;
    private const ushort BindingRequest = 0x0001;
    private const ushort BindingSuccess = 0x0101;
    private const ushort XorMappedAddress = 0x0020;

    /// <summary>Writes a Binding request with the given 12-byte transaction id. Returns the datagram length (20).</summary>
    public static int WriteBindingRequest(Span<byte> destination, ReadOnlySpan<byte> transactionId)
    {
        BinaryPrimitives.WriteUInt16BigEndian(destination, BindingRequest);
        BinaryPrimitives.WriteUInt16BigEndian(destination[2..], 0);
        BinaryPrimitives.WriteUInt32BigEndian(destination[4..], MagicCookie);
        transactionId[..TransactionIdSize].CopyTo(destination[8..]);
        return HeaderSize;
    }

    /// <summary>True when <paramref name="datagram"/> is a well-formed Binding request; yields its transaction id.</summary>
    public static bool TryReadBindingRequest(ReadOnlySpan<byte> datagram, out ReadOnlySpan<byte> transactionId)
    {
        transactionId = default;
        if (datagram.Length < HeaderSize
            || BinaryPrimitives.ReadUInt16BigEndian(datagram) != BindingRequest
            || BinaryPrimitives.ReadUInt32BigEndian(datagram[4..]) != MagicCookie
            || BinaryPrimitives.ReadUInt16BigEndian(datagram[2..]) != datagram.Length - HeaderSize)
        {
            return false;
        }
        transactionId = datagram.Slice(8, TransactionIdSize);
        return true;
    }

    /// <summary>Writes the success response telling the requester the address its request came from (IPv4). Returns the length.</summary>
    public static int WriteBindingSuccess(Span<byte> destination, ReadOnlySpan<byte> transactionId, IPEndPoint observed)
    {
        if (observed.AddressFamily != AddressFamily.InterNetwork)
        {
            throw new NotSupportedException("Only IPv4 addresses are supported.");
        }

        const int attributeLength = 8;
        BinaryPrimitives.WriteUInt16BigEndian(destination, BindingSuccess);
        BinaryPrimitives.WriteUInt16BigEndian(destination[2..], 4 + attributeLength);
        BinaryPrimitives.WriteUInt32BigEndian(destination[4..], MagicCookie);
        transactionId[..TransactionIdSize].CopyTo(destination[8..]);

        Span<byte> attribute = destination[HeaderSize..];
        BinaryPrimitives.WriteUInt16BigEndian(attribute, XorMappedAddress);
        BinaryPrimitives.WriteUInt16BigEndian(attribute[2..], attributeLength);
        attribute[4] = 0;
        attribute[5] = 0x01; // IPv4
        BinaryPrimitives.WriteUInt16BigEndian(attribute[6..], (ushort)(observed.Port ^ (int)(MagicCookie >> 16)));
        Span<byte> address = stackalloc byte[4];
        observed.Address.TryWriteBytes(address, out _);
        BinaryPrimitives.WriteUInt32BigEndian(attribute[8..], BinaryPrimitives.ReadUInt32BigEndian(address) ^ MagicCookie);
        return HeaderSize + 4 + attributeLength;
    }

    /// <summary>Reads a Binding success response for <paramref name="expectedTransactionId"/> and returns the mapped address.</summary>
    public static bool TryReadBindingSuccess(ReadOnlySpan<byte> datagram, ReadOnlySpan<byte> expectedTransactionId, out IPEndPoint? mapped)
    {
        mapped = null;
        if (datagram.Length < HeaderSize
            || BinaryPrimitives.ReadUInt16BigEndian(datagram) != BindingSuccess
            || BinaryPrimitives.ReadUInt32BigEndian(datagram[4..]) != MagicCookie
            || !datagram.Slice(8, TransactionIdSize).SequenceEqual(expectedTransactionId[..TransactionIdSize]))
        {
            return false;
        }

        int length = BinaryPrimitives.ReadUInt16BigEndian(datagram[2..]);
        ReadOnlySpan<byte> attributes = datagram[HeaderSize..];
        if (length > attributes.Length)
        {
            return false;
        }
        attributes = attributes[..length];

        while (attributes.Length >= 4)
        {
            ushort type = BinaryPrimitives.ReadUInt16BigEndian(attributes);
            int valueLength = BinaryPrimitives.ReadUInt16BigEndian(attributes[2..]);
            if (valueLength > attributes.Length - 4)
            {
                return false;
            }

            ReadOnlySpan<byte> value = attributes.Slice(4, valueLength);
            if (type == XorMappedAddress && valueLength >= 8 && value[1] == 0x01)
            {
                int port = BinaryPrimitives.ReadUInt16BigEndian(value[2..]) ^ (int)(MagicCookie >> 16);
                uint address = BinaryPrimitives.ReadUInt32BigEndian(value[4..]) ^ MagicCookie;
                Span<byte> bytes = stackalloc byte[4];
                BinaryPrimitives.WriteUInt32BigEndian(bytes, address);
                mapped = new IPEndPoint(new IPAddress(bytes), port);
                return true;
            }

            // Attributes are padded to a multiple of four bytes.
            int advance = 4 + ((valueLength + 3) & ~3);
            if (advance > attributes.Length)
            {
                break;
            }
            attributes = attributes[advance..];
        }
        return false;
    }
}
