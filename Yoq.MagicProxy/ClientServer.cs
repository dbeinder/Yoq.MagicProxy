using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
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
        private const bool UseSsl = true;
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
            Stream dataStream = null;
            var clientEndPoint = client?.Client?.RemoteEndPoint;
            try
            {
                var tcpStream = client.GetStream();
                tcpStream.ReadTimeout = 5000;
                tcpStream.WriteTimeout = 5000;

                if (UseSsl)
                {
                    sslStream = new SslStream(tcpStream, false);
                    await sslStream.AuthenticateAsServerAsync(_serverCertificate, false, false).ConfigureAwait(false);
                }

                dataStream = UseSsl ? (Stream) sslStream : tcpStream;
                Console.WriteLine($"[{clientEndPoint}] Client connected");

                while (true)
                {
                    var (success, clientInfo, _, reqBytes) = await dataStream.ReadMessageAsync(ct).ConfigureAwait(false);
                    if (!success) break;

                    switch (clientInfo.ServerAction)
                    {
                        case ServerAction.None: break;
                        //case ServerAction.Logout: authenticated = false; break;
                        default: throw new Exception($"[{clientEndPoint}] unknown server action: [{clientInfo.ServerAction}]");
                    }

                    var errData = new byte[0];
                    var responseData = new byte[0];

                    if (reqBytes.Length > 0)
                    {
                        var request = Encoding.UTF8.GetString(reqBytes);

                        var publicRequest = (clientInfo.ClientFlags & ClientFlags.PublicRequest) > 0;
                        var impl = publicRequest ? _publicDispatcher : _authenticatedDispatcher;

                        if (!publicRequest && !authenticated)
                            throw new Exception($"[{clientEndPoint}] Received request from unauthenticated connection!");

                        var sw = Stopwatch.StartNew();
                        var (err, res, code, type) = await impl.DoRequestRaw(request).ConfigureAwait(false);
                        sw.Stop();
                        Console.Write($"[{clientEndPoint}] Request [{code}] exec: {sw.ElapsedMilliseconds}ms");

                        if (err == null)
                        {
                            switch (type)
                            {
                                case MagicMethodType.Normal: break;
                                case MagicMethodType.Authenticate:
                                    if (res is bool b) authenticated = b;
                                    else Console.WriteLine($"[{clientEndPoint}] Authenticate method returned: [{res}]");
                                    break;
                                case MagicMethodType.CancelAuthentication:
                                    if (res is bool doCancel && doCancel) authenticated = false;
                                    else Console.WriteLine($"[{clientEndPoint}] CancelAuthentication method returned: [{res}]");
                                    break;
                            }

                            responseData = impl.Serialize(res);
                        }
                        else errData = Encoding.UTF8.GetBytes(err);
                    }

                    var info = new MessageInfo { ServerFlags = authenticated ? ServerFlags.IsAuthenticated : ServerFlags.None };

                    var sw1 = Stopwatch.StartNew();
                    await dataStream.WriteMessageAsync(info, errData, responseData, ct).ConfigureAwait(false);
                    sw1.Stop();
                    Console.WriteLine($" response send: {sw1.ElapsedMilliseconds}ms");
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
                Console.WriteLine($"[{clientEndPoint}] Exception: " + e);
            }
            finally
            {
                Console.WriteLine($"[{clientEndPoint}] Client disconnected");
                dataStream?.Close();
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
        private int _lastResponseTimeMs;
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
        public int LastResponseTimeMs
        {
            get => _lastResponseTimeMs;
            protected set { _lastResponseTimeMs = value; InvokePropertyChanged(); }
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
                
                var sw = new Stopwatch();
                sw.Start();
                var queryRes = await fn().ConfigureAwait(false);
                sw.Stop();
                LastResponseTimeMs = (int)sw.ElapsedMilliseconds;

                return queryRes;
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
        private const bool UseSsl = true;
        private readonly int _port;
        private readonly string _server;
        private readonly X509Certificate2 _caCert;

        private Stream _dataStream;
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
            var tcpStream = _tcpClient.GetStream();

            if (UseSsl)
            {
                _sslStream = new SslStream(tcpStream, false, ValidateServerCertificate, null);
                await _sslStream.AuthenticateAsClientAsync(commonName).ConfigureAwait(false);
            }

            _dataStream = UseSsl ? (Stream)_sslStream : tcpStream;
            Connected = true;
        }

        public override async Task DisconnectAsync()
        {
            if (!Connected || _dataStream == null) return;
            try
            {
                if(UseSsl) await _sslStream.ShutdownAsync().ConfigureAwait(false);
                _tcpClient?.Close();
            }
            catch (Exception) { }
            Connected = false;
        }

        private Task<(bool, MessageInfo, byte[], byte[])> QueryServerSafely(MessageInfo info, byte[] reqBytes) =>
            RunQuerySequentially(async () =>
            {
                await _dataStream.WriteMessageAsync(info, null, reqBytes, CancellationToken.None).ConfigureAwait(false);
                var result = await _dataStream.ReadMessageAsync(CancellationToken.None).ConfigureAwait(false);
                var (readSuccessful, srvInfo, _, _) = result;
                if(readSuccessful) HandleServerResponse(srvInfo);
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