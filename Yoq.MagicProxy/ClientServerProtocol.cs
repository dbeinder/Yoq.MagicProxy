using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Security;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Yoq.MagicProxy
{
    [Flags]
    internal enum ServerFlags : uint
    {
        None = 0x00,
        IsAuthenticated = 0x01
    }

    [Flags]
    internal enum ClientFlags : uint
    {
        None = 0x00,
        PublicRequest = 0x01
    }

    internal enum ServerAction : byte
    {
        None = 0x00,
        Logout = 0x01
    }

    internal enum ClientAction : byte
    {
        None = 0x00
    }

    internal class MessageInfo
    {
        //for use by server
        public ClientFlags ClientFlags;
        public ServerAction ServerAction;

        //for use by client
        public ServerFlags ServerFlags;
        public ClientAction ClientAction;

        public byte[] ToBytes() => new[] { (byte)ClientFlags, (byte)ServerAction, (byte)ServerFlags, (byte)ClientAction };

        public static MessageInfo FromArray(byte[] data, int offset)
        {
            if (offset + 4 > data.Length) throw new ArgumentException("input array too small");
            return new MessageInfo
            {
                ClientFlags = (ClientFlags)data[offset],
                ServerAction = (ServerAction)data[offset + 1],
                ServerFlags = (ServerFlags)data[offset + 2],
                ClientAction = (ClientAction)data[offset + 3]
            };
        }
    }

    //format: [MessageInfo: 4B][ErrLen: 4B][DataLen: 4B][ExtLen: 4B][Err: string][Data][Ext]
    internal static class SslStreamExtensions
    {
        public static async Task<(bool, MessageInfo, byte[], byte[])> ReadMessageAsync(this SslStream stream, CancellationToken ct)
        {
            var header = new byte[16];
            var readCnt = await stream.ReadAsync(header, 0, 16, ct).ConfigureAwait(false);
            if (readCnt == 0) return (false, null, null, null);
            var info = MessageInfo.FromArray(header, 0);
            var errLen = BitConverter.ToInt32(header, 4);
            var datLen = BitConverter.ToInt32(header, 8);
            var extLen = BitConverter.ToInt32(header, 12);

            var totalLen = errLen + extLen + datLen;
            if (totalLen > MagicProxySettings.MaxMessageSize) throw new Exception($"received message too long: {totalLen}");

            var errBuffer = errLen == 0 ? null : new byte[errLen];
            var datBuffer = datLen == 0 ? null : new byte[datLen];
            var extBuffer = extLen == 0 ? null : new byte[extLen];

            if (errLen > 0)
            {
                readCnt = await stream.ReadAsync(errBuffer, 0, errLen, ct).ConfigureAwait(false);
                if (readCnt == 0) return (false, info, null, null);
            }

            if (datLen > 0)
            {
                readCnt = await stream.ReadAsync(datBuffer, 0, datLen, ct).ConfigureAwait(false);
                if (readCnt == 0) return (false, info, null, null);
            }

            if (extLen > 0) //block for future backwards-compatible protocol extensions
            {
                readCnt = await stream.ReadAsync(extBuffer, 0, extLen, ct).ConfigureAwait(false);
                if (readCnt == 0) return (false, info, null, null);
            }

            return (true, info, errBuffer, datBuffer);
        }

        public static async Task WriteMessageAsync(this SslStream stream, MessageInfo info, byte[] err, byte[] data, CancellationToken ct)
        {
            var totalLen = (err?.Length ?? 0) + (data?.Length ?? 0);
            if (totalLen > MagicProxySettings.MaxMessageSize) throw new Exception($"message to be sent is too long: {totalLen}");
            var header = info.ToBytes()
                .Concat(BitConverter.GetBytes((Int32)(err?.Length ?? 0)))
                .Concat(BitConverter.GetBytes((Int32)(data?.Length ?? 0)))
                .Concat(BitConverter.GetBytes((Int32)0))
                .ToArray();
            await stream.WriteAsync(header, 0, 16, ct).ConfigureAwait(false);
            if (err?.Length > 0) await stream.WriteAsync(err, 0, err.Length, ct).ConfigureAwait(false);
            if (data?.Length > 0) await stream.WriteAsync(data, 0, data.Length, ct).ConfigureAwait(false);
            await stream.FlushAsync(ct).ConfigureAwait(false);
        }
    }
}
