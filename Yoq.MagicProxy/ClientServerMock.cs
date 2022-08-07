using System;
using System.IO;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Yoq.MagicProxy
{
    public sealed class MagicProxyMockConnection<TInterface, TConnectionState>
        : MagicProxyClientBase<TInterface, TConnectionState>
        where TInterface : class
    {
        public TimeSpan RequestDelay = TimeSpan.Zero;
        public Action<string, string, byte[]> WireSniffer;

        private readonly IMagicDispatcher<TInterface> _dispatcher = new MagicDispatcher<TInterface>();
        private readonly IMagicInterfaceImpl<TConnectionState> _impl;
        private readonly TInterface _implAsInterface;

        public override async Task ConnectAsync()
        {
            _impl.RemoteEndPoint = new IPEndPoint(IPAddress.Loopback, 5555);
            _impl.ClientCertificate = new X509Certificate2();
            await _impl.ApproveConnection().ConfigureAwait(false);
            HandleConnectionStateUpdate(_impl.ConnectionStateUInt);
            Connected = true;
        }

        public override Task DisconnectAsync()
        {
            Connected = false;
            return Task.CompletedTask;
        }

        protected override Task<(string, byte[])> DoRequestImpl(string request) =>
            RunQuerySequentially(async () =>
            {
                await Task.Delay(RequestDelay).ConfigureAwait(false);
                var req = JArray.Load(new JsonTextReader(
                        //stop Json.Net from speculatively parsing any date/times without any rules
                        new StringReader(request))
                { DateParseHandling = DateParseHandling.None });

                if (req.Count != 3) throw new ArgumentException("invalid JSON request");
                var method = req[0].ToObject<string>();
                var tArgs = req[1] as JArray;
                var args = req[2] as JArray;
                var (err, obj) = await _dispatcher.ExecuteRequest(_implAsInterface, method, tArgs, args).ConfigureAwait(false);
                HandleConnectionStateUpdate(_impl.ConnectionStateUInt);
                var response = _dispatcher.SerializeResponse(obj);
                WireSniffer?.Invoke(request, err, response);
                return (err, response);
            });

        public MagicProxyMockConnection(IMagicInterfaceImpl<TConnectionState> impl)
        {
            _impl = impl;
            _implAsInterface = impl as TInterface;
            if (_implAsInterface == null) throw new ArgumentException($"impl must be {typeof(TInterface).Name}");
        }
    }
}
