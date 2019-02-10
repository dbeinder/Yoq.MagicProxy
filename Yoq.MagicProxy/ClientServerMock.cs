using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;

namespace Yoq.MagicProxy
{
    public sealed class MagicProxyMockConnection<TIPublic, TPublicProxy, TIAuthenticated, TAuthenticatedProxy>
        : MagicProxyClientBase<TPublicProxy, TAuthenticatedProxy>, IMagicConnection<TPublicProxy, TAuthenticatedProxy>
        where TPublicProxy : MagicProxyBase, TIPublic, new()
        where TAuthenticatedProxy : MagicProxyBase, TIAuthenticated, new()
    {
        public TimeSpan RequestDelay = TimeSpan.Zero;
        public Action<string, string, byte[]> WireSniffer;

        private readonly IMagicDispatcherRaw _publicDispatcher;
        private readonly IMagicDispatcherRaw _authenticatedDispatcher;

        public override Task ConnectAsync()
        {
            Connected = true;
            return Task.CompletedTask;
        }

        public override Task DisconnectAsync()
        {
            Connected = false;
            return Task.CompletedTask;
        }

        protected override Task<(string, byte[])> DoRequest(string request, bool publicRequest) =>
            RunQuerySequentially(async () =>
            {
                await Task.Delay(RequestDelay).ConfigureAwait(false);
                var impl = publicRequest ? _publicDispatcher : _authenticatedDispatcher;
                var (err, obj, typ) = await impl.DoRequestRaw(request).ConfigureAwait(false);
                if (err == null && typ == MagicMethodType.Authenticate && obj is bool b) Authenticated = b;
                var response = impl.Serialize(obj);
                WireSniffer?.Invoke(request, err, response);
                return (err, response);
            });

        public MagicProxyMockConnection(TIPublic publicImpl, TIAuthenticated authImpl)
        {
            _publicDispatcher = new MagicDispatcher<TIPublic>(publicImpl);
            _authenticatedDispatcher = new MagicDispatcher<TIAuthenticated>(authImpl);
        }
    }
}
