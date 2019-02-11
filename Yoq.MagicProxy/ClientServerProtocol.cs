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
        None = 0x00
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

        public byte[] ToBytes() => new[]
            {(byte) ClientFlags, (byte) ServerAction, (byte) ServerFlags, (byte) ClientAction};

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
        private const int ChunkSize = 16000;

        private static async Task WriteChunkedAsync(this SslStream ssl, byte[] buffer, CancellationToken ct)
        {
            var pos = 0;
            while (pos != buffer.Length)
            {
                var left = buffer.Length - pos;
                var writeSize = left > ChunkSize ? ChunkSize : left;
                await ssl.WriteAsync(buffer, pos, writeSize, ct).ConfigureAwait(false);
                pos += writeSize;
            }
        }

        private static async Task<(bool, byte[])> ReadChunkedAsync(this SslStream ssl, int length, CancellationToken ct)
        {
            var buffer = new byte[length];
            var pos = 0;

            while (pos != buffer.Length)
            {
                var left = buffer.Length - pos;
                var readSize = left > ChunkSize ? ChunkSize : left;
                var readCnt = await ssl.ReadAsync(buffer, pos, readSize, ct).ConfigureAwait(false);
                if (readCnt != readSize) return (false, null);
                pos += readSize;
            }
            return (true, buffer);
        }

        public static async Task<(bool, MessageInfo, byte[], byte[])> ReadMessageAsync(this SslStream stream,
            CancellationToken ct)
        {
            var (headerRead, header) = await stream.ReadChunkedAsync(16, ct).ConfigureAwait(false);
            if (!headerRead) return (false, null, null, null);

            var info = MessageInfo.FromArray(header, 0);
            var errLen = BitConverter.ToInt32(header, 4);
            var datLen = BitConverter.ToInt32(header, 8);
            var extLen = BitConverter.ToInt32(header, 12);

            var totalLen = errLen + extLen + datLen;
            if (totalLen > MagicProxySettings.MaxMessageSize)
                throw new Exception($"received message too long: {totalLen}");

            var (errRead, errBuffer) = await stream.ReadChunkedAsync(errLen, ct).ConfigureAwait(false);
            if (!errRead) return (false, null, null, null);
            var (datRead, datBuffer) = await stream.ReadChunkedAsync(datLen, ct).ConfigureAwait(false);
            if (!datRead) return (false, null, null, null);
            var (extRead, extBuffer) = await stream.ReadChunkedAsync(extLen, ct).ConfigureAwait(false);
            if (!extRead) return (false, null, null, null);
            
            return (true, info, errBuffer, datBuffer);
        }

        public static async Task WriteMessageAsync(this SslStream stream, MessageInfo info, byte[] err, byte[] data,
            CancellationToken ct)
        {
            var totalLen = (err?.Length ?? 0) + (data?.Length ?? 0);
            if (totalLen > MagicProxySettings.MaxMessageSize)
                throw new Exception($"message to be sent is too long: {totalLen}");
            var header = info.ToBytes()
                .Concat(BitConverter.GetBytes((Int32)(err?.Length ?? 0)))
                .Concat(BitConverter.GetBytes((Int32)(data?.Length ?? 0)))
                .Concat(BitConverter.GetBytes((Int32)0))
                .ToArray();
            await stream.WriteChunkedAsync(header, ct).ConfigureAwait(false);
            if (err?.Length > 0) await stream.WriteChunkedAsync(err, ct).ConfigureAwait(false);
            if (data?.Length > 0) await stream.WriteChunkedAsync(data, ct).ConfigureAwait(false);
            await stream.FlushAsync(ct).ConfigureAwait(false);
        }
    }
}