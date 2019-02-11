using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Yoq.MagicProxy
{
    public sealed class MagicProxyServer<TIPublic, TIAuthenticated>
    {
        private readonly IMagicDispatcherRaw _publicDispatcher;
        private readonly IMagicDispatcherRaw _authenticatedDispatcher;

        private readonly X509Certificate2 _serverCertificate;
        private readonly int _port;

        private Task _serverLoop;
        private CancellationTokenSource _cancelSource;

        public MagicProxyServer(TIPublic publicImpl, TIAuthenticated authenticatedImpl, int port, X509Certificate2 privCert)
        {
            _publicDispatcher = new MagicDispatcher<TIPublic>(publicImpl);
            _authenticatedDispatcher = new MagicDispatcher<TIAuthenticated>(authenticatedImpl);
            _port = port;
            _serverCertificate = privCert;
        }

        public void StartServer()
        {
            StopServer();
            _cancelSource = new CancellationTokenSource();
            _serverLoop = Task.Factory.StartNew(ServerLoop, TaskCreationOptions.LongRunning);
        }

        public void StopServer() => _cancelSource?.Cancel();

        private void ServerLoop()
        {
            TcpListener listener = null;

            try
            {
                listener = new TcpListener(IPAddress.Any, _port);
                listener.Start();

                while (true)
                {
                    var waitForClient = listener.AcceptTcpClientAsync();
                    waitForClient.Wait(_cancelSource.Token);
                    ClientConnection(waitForClient.Result, _cancelSource.Token);
                }
            }
            catch (Exception e)
            {
                switch (e)
                {
                    case OperationCanceledException o:
                    case System.IO.IOException x:
                        return;
                }
                Console.WriteLine("ServerLoop: Exception: " + e);
            }
            finally
            {
                listener?.Stop();
            }
        }

        private async void ClientConnection(TcpClient client, CancellationToken ct)
        {
            var authenticated = false;
            SslStream sslStream = null;

            try
            {
                sslStream = new SslStream(client.GetStream(), false);
                await sslStream.AuthenticateAsServerAsync(_serverCertificate, false, false).ConfigureAwait(false);
                sslStream.ReadTimeout = 5000;
                sslStream.WriteTimeout = 5000;

                while (true)
                {
                    var (success, clientInfo, _, reqBytes) = await sslStream.ReadMessageAsync(ct).ConfigureAwait(false);
                    if (!success) break;

                    switch (clientInfo.ServerAction)
                    {
                        case ServerAction.None: break;
                        //case ServerAction.Logout: authenticated = false; break;
                        default: throw new Exception($"unknown server action: [{clientInfo.ServerAction}]");
                    }

                    var errData = new byte[0];
                    var responseData = new byte[0];

                    if (reqBytes.Length > 0)
                    {
                        var request = Encoding.UTF8.GetString(reqBytes);

                        var publicRequest = (clientInfo.ClientFlags & ClientFlags.PublicRequest) > 0;
                        var impl = publicRequest ? _publicDispatcher : _authenticatedDispatcher;

                        if (!publicRequest && !authenticated)
                            throw new Exception("Received request from unauthenticated connection!");

                        var (err, res, type) = await impl.DoRequestRaw(request).ConfigureAwait(false);
                        if (err == null)
                        {
                            switch (type)
                            {
                                case MagicMethodType.Normal: break;
                                case MagicMethodType.Authenticate:
                                    if (res is bool b) authenticated = b;
                                    else Console.WriteLine($"Authenticate method returned: [{res}]");
                                    break;
                                case MagicMethodType.CancelAuthentication:
                                    if (res is bool doCancel && doCancel) authenticated = false;
                                    else Console.WriteLine($"CancelAuthentication method returned: [{res}]");
                                    break;
                            }

                            responseData = impl.Serialize(res);
                        }
                        else errData = Encoding.UTF8.GetBytes(err);
                    }

                    var info = new MessageInfo { ServerFlags = authenticated ? ServerFlags.IsAuthenticated : ServerFlags.None };
                    await sslStream.WriteMessageAsync(info, errData, responseData, ct).ConfigureAwait(false);
                }
            }
            catch (Exception e)
            {
                switch (e)
                {
                    case OperationCanceledException o:
                    case System.IO.IOException x:
                        return;
                }
                Console.WriteLine("ClientConnection: Exception: " + e);
            }
            finally
            {
                Console.WriteLine("Closing client connection....");
                sslStream?.Close();
                client?.Close();
            }
        }
    }

    public abstract class MagicProxyClientBase<TPublicProxy, TAuthenticatedProxy>
        where TPublicProxy : MagicProxyBase, new()
        where TAuthenticatedProxy : MagicProxyBase, new()
    {
        private readonly SemaphoreSlim _sendQueueCounter = new SemaphoreSlim(0, Int32.MaxValue);
        private readonly SemaphoreSlim _sendLock = new SemaphoreSlim(1, 1);

        public event PropertyChangedEventHandler PropertyChanged;

        public TPublicProxy PublicProxy { get; }
        public TAuthenticatedProxy AuthenticatedProxy { get; }

        private bool _busy, _connected, _authenticated;
        public bool Busy
        {
            get => _busy;
            protected set { _busy = value; InvokePropertyChanged(); }
        }
        public bool Connected
        {
            get => _connected;
            protected set { _connected = value; InvokePropertyChanged(); }
        }
        public bool Authenticated
        {
            get => _authenticated;
            protected set { _authenticated = value; InvokePropertyChanged(); }
        }

        private void InvokePropertyChanged([CallerMemberName] string name = null)
            => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));

        private class DispatcherShim : IMagicDispatcher
        {
            public bool PublicRequest;
            public MagicProxyClientBase<TPublicProxy, TAuthenticatedProxy> ProxyClient;
            public Task<(string, byte[])> DoRequest(string request) => ProxyClient.DoRequest(request, PublicRequest);
        }

        internal MagicProxyClientBase()
        {
            PublicProxy = new TPublicProxy();
            AuthenticatedProxy = new TAuthenticatedProxy();
            PublicProxy.MagicDispatcher = new DispatcherShim { ProxyClient = this, PublicRequest = true };
            AuthenticatedProxy.MagicDispatcher = new DispatcherShim { ProxyClient = this, PublicRequest = false };
        }

        protected async Task<TRet> RunQuerySequentially<TRet>(Func<Task<TRet>> fn)
        {
            try
            {
                if (_sendQueueCounter.Release() == 0) Busy = true;
                await _sendLock.WaitAsync().ConfigureAwait(false);
                if (!Connected) throw new Exception("Proxy not connected");
                return await fn().ConfigureAwait(false);
            }
            finally
            {
                _sendLock.Release();
                await _sendQueueCounter.WaitAsync().ConfigureAwait(false);
                if (_sendQueueCounter.CurrentCount == 0) Busy = false;
            }
        }

        public abstract Task ConnectAsync();

        public abstract Task DisconnectAsync();

        protected abstract Task<(string, byte[])> DoRequest(string request, bool publicRequest);
    }

    public sealed class MagicProxyClient<TPublicProxy, TAuthenticatedProxy> : MagicProxyClientBase<TPublicProxy, TAuthenticatedProxy>, IMagicConnection<TPublicProxy, TAuthenticatedProxy>
        where TPublicProxy : MagicProxyBase, new()
        where TAuthenticatedProxy : MagicProxyBase, new()
    {

        private readonly int _port;
        private readonly string _server;
        private readonly X509Certificate2 _caCert;

        private SslStream _sslStream;
        private TcpClient _tcpClient;

        public MagicProxyClient(string server, int port, X509Certificate2 pubCert)
        {
            _server = server;
            _port = port;
            _caCert = pubCert;
        }

        public override async Task ConnectAsync()
        {
            if (Connected) throw new Exception("Already connected");

            var commonName = _caCert.GetNameInfo(X509NameType.SimpleName, false);

            _tcpClient = new TcpClient();
            await _tcpClient.ConnectAsync(_server, _port).ConfigureAwait(false);
            _sslStream = new SslStream(_tcpClient.GetStream(), false, ValidateServerCertificate, null);

            await _sslStream.AuthenticateAsClientAsync(commonName).ConfigureAwait(false);
            Connected = true;
        }

        public override async Task DisconnectAsync()
        {
            if (!Connected || _sslStream == null) return;
            try
            {
                await _sslStream.ShutdownAsync().ConfigureAwait(false);
                _tcpClient?.Close();
            }
            catch (Exception) { }
            Connected = false;
        }

        private Task<(bool, MessageInfo, byte[], byte[])> QueryServerSafely(MessageInfo info, byte[] reqBytes) =>
            RunQuerySequentially(async () =>
            {
                await _sslStream.WriteMessageAsync(info, null, reqBytes, CancellationToken.None).ConfigureAwait(false);
                var result = await _sslStream.ReadMessageAsync(CancellationToken.None).ConfigureAwait(false);
                HandleServerResponse(result.Item2);
                return result;
            });

        private void HandleServerResponse(MessageInfo srvInfo)
        {
            Authenticated = (srvInfo.ServerFlags & ServerFlags.IsAuthenticated) > 0;
            switch (srvInfo.ClientAction)
            {
                case ClientAction.None: break;
                default: throw new Exception($"unknown server action: [{srvInfo.ClientAction}]");
            }
        }

        protected override async Task<(string, byte[])> DoRequest(string request, bool publicRequest)
        {
            if (!publicRequest && !Authenticated) throw new Exception("Proxy not authenticated");
            var requestBytes = Encoding.UTF8.GetBytes(request);
            var info = new MessageInfo { ClientFlags = publicRequest ? ClientFlags.PublicRequest : ClientFlags.None };

            var (success, _, err, resp) = await QueryServerSafely(info, requestBytes).ConfigureAwait(false);
            if (!success) throw new Exception("No response from server");
            var errString = err.Length > 0 ? Encoding.UTF8.GetString(err) : null;
            return (errString, resp);
        }

        private bool ValidateServerCertificate(
              object sender,
              X509Certificate certificate,
              X509Chain chain,
              SslPolicyErrors sslPolicyErrors)
        {
            //ignore RemoteCertificateChainErrors
            sslPolicyErrors &= ~SslPolicyErrors.RemoteCertificateChainErrors;
            if (certificate.GetPublicKeyString() != _caCert.GetPublicKeyString())
                return false;
            return sslPolicyErrors == SslPolicyErrors.None;
        }
    }
}