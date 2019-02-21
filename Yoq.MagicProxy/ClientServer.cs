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
using Common.Logging;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Yoq.MagicProxy
{
    public sealed class MagicProxyServer<TInterface, TImpl, TConnectionState>
        where TInterface : class
        where TImpl : class, TInterface, IMagicBackendImpl<TConnectionState>
    {
        public bool Logging = false;
        private readonly bool _useSsl;
        private readonly ILog _log;
        private readonly IMagicDispatcherRaw<TInterface> _dispatcher;
        private readonly Func<TImpl> _implFactory;

        private readonly X509Certificate2 _serverCertificate;
        private readonly X509Certificate2 _clientCa;
        private readonly IPEndPoint _listenEndPoint;

        private Task _serverLoop;
        private CancellationTokenSource _cancelSource;
        private readonly Dictionary<string, MethodEntry> _methodTable;

        /// <param name="serverPrivCert">If null, MagicProxy uses a plaintext TCP connection</param>
        /// <param name="clientCa">If null, the client certificate is not verified</param>
        public MagicProxyServer(Func<TImpl> implFactory, IPEndPoint listenEndPoint, ILog log = null, X509Certificate2 serverPrivCert = null, X509Certificate2 clientCa = null)
        {
            _methodTable = MagicProxyHelper.ReadInterfaceMethods<TInterface, MethodEntry>();
            _dispatcher = new MagicDispatcher<TInterface>();
            _implFactory = implFactory;
            _listenEndPoint = listenEndPoint;
            _log = log ?? new Common.Logging.Simple.NoOpLogger();
            if (serverPrivCert != null)
            {
                if (!serverPrivCert.HasPrivateKey) throw new ArgumentException("server certificate need private key");
                _useSsl = true;
                _serverCertificate = serverPrivCert;
                _clientCa = clientCa;
            }
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
                listener = new TcpListener(_listenEndPoint);
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
                _log.Error("ServerLoop Exception: " + e);
            }
            finally
            {
                listener?.Stop();
            }
        }

        private async void ClientConnection(TcpClient client, CancellationToken ct)
        {
            var clientEndPoint = client?.Client?.RemoteEndPoint;
            var impl = _implFactory();
            impl.RemoteEndPoint = clientEndPoint;

            SslStream sslStream = null;
            Stream dataStream = null;
            try
            {
                _log.Info(m => m($"[{clientEndPoint}] Client connected"));

                var tcpStream = client.GetStream();
                tcpStream.ReadTimeout = 5000;
                tcpStream.WriteTimeout = 5000;

                if (_useSsl)
                {
                    sslStream = new SslStream(tcpStream, false, UserCertificateValidationCallback, null, EncryptionPolicy.RequireEncryption);
                    await sslStream.AuthenticateAsServerAsync(_serverCertificate, true, false).ConfigureAwait(false);
                    _log.Debug(m => m($"[{clientEndPoint}] SSL: {sslStream.SslProtocol}, {sslStream.CipherAlgorithm}, {sslStream.HashAlgorithm}, {sslStream.KeyExchangeAlgorithm}"));
                    if (!sslStream.IsSigned || !sslStream.IsEncrypted) throw new Exception("Non secure connection");
                    impl.ClientCertificate = sslStream.RemoteCertificate == null ? null : new X509Certificate2(sslStream.RemoteCertificate);
                }
                dataStream = _useSsl ? (Stream)sslStream : tcpStream;

                var connError = await impl.ValidateConnection().ConfigureAwait(false);
                var connErrorBytes = connError == null ? null : Encoding.UTF8.GetBytes(connError);
                await dataStream.WriteMessageAsync(impl.ConnectionStateUInt, connErrorBytes, null, ct).ConfigureAwait(false);
                if (connError != null)
                {
                    _log.Info(m => m($"[{clientEndPoint}] Client declined by Impl: {connError}"));
                    return;
                }

                while (true)
                {
                    var (success, clientState, _, reqBytes) = await dataStream.ReadMessageAsync(ct).ConfigureAwait(false);
                    if (!success) break;

                    string errMsg = null;
                    var responseData = new byte[0];
                    string dbgQuery = "<none>";
                    long dbgExecTime = 0;

                    if (reqBytes.Length > 0)
                    {
                        var request = Encoding.UTF8.GetString(reqBytes);
                        try
                        {
                            var req = JArray.Load(new JsonTextReader(
                                    //stop Json.Net from speculatively parsing any date/times without any rules
                                    new StringReader(request))
                            { DateParseHandling = DateParseHandling.None });

                            if (req.Count != 3) throw new ArgumentException("invalid JSON request");
                            var method = req[0].ToObject<string>();
                            var tArgs = req[1] as JArray;
                            var args = req[2] as JArray;

                            if (!_methodTable.TryGetValue(method, out var methodEntry))
                            {
                                errMsg = $"Method [{method}] not found";
                                _log.Warn($"[{clientEndPoint}] " + errMsg);
                            }
                            else if ((methodEntry.RequiredFlags & ~impl.ConnectionStateUInt) is var missing && missing > 0)
                            {
                                errMsg = $"Method [{method}] is not allowed, state(s) missing: [{(TConnectionState)(object)missing}]";
                                _log.Warn($"[{clientEndPoint}] " + errMsg);
                            }
                            else
                            {
                                var sw = Stopwatch.StartNew();
                                var (err, res) = await _dispatcher.DoRequestRaw(impl, method, tArgs, args).ConfigureAwait(false);
                                sw.Stop();
                                dbgExecTime = sw.ElapsedMilliseconds;
                                dbgQuery = method;

                                if (err == null)
                                {
                                    responseData = _dispatcher.Serialize(res);
                                }
                                else
                                {
                                    errMsg = "Impl Exception: " + err;
                                    _log.Error($"[{clientEndPoint}] " + errMsg);
                                }
                            }
                        }
                        catch (Exception e)
                        {
                            errMsg = "Parse/Dispatch Exception " + e;
                            _log.Error($"[{clientEndPoint}] " + errMsg);
                        }
                    }

                    var sw1 = Stopwatch.StartNew();
                    var errData = errMsg == null ? new byte[0] : Encoding.UTF8.GetBytes(errMsg);
                    await dataStream.WriteMessageAsync(impl.ConnectionStateUInt, errData, responseData, ct).ConfigureAwait(false);
                    sw1.Stop();

                    _log.Debug($"[{clientEndPoint}] run:{(dbgExecTime + "ms"),6} tx:{(sw1.ElapsedMilliseconds + "ms"),6} {dbgQuery}");
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
                _log.Error($"[{clientEndPoint}] Connection Exception: " + e);
            }
            finally
            {
                _log.Info(m => m($"[{clientEndPoint}] Client disconnected"));
                dataStream?.Close();
                client.Close();
            }
        }

        private bool UserCertificateValidationCallback(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            if (_clientCa == null) return true;
            return MagicProxyHelper.VerifyChainWithCa(chain, sslPolicyErrors, _clientCa);
        }
    }

    public abstract class MagicProxyClientBase<TInterface, TConnectionState> : IMagicDispatcher
        where TInterface : class
    {
        private readonly SemaphoreSlim _sendQueueCounter = new SemaphoreSlim(0, Int32.MaxValue);
        private readonly SemaphoreSlim _sendLock = new SemaphoreSlim(1, 1);

        public event PropertyChangedEventHandler PropertyChanged;

        internal readonly Dictionary<string, MethodEntry> MethodTable;
        public TInterface Proxy { get; }

        private bool _busy, _connected;
        private uint _connectionStateUint;
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

        public TConnectionState ConnectionState => (TConnectionState)Enum.ToObject(typeof(TConnectionState), _connectionStateUint);
        private void ConnectionStateChanged() => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(ConnectionState)));

        protected void HandleConnectionStateUpdate(uint newState)
        {
            if (_connectionStateUint == newState) return;
            _connectionStateUint = newState;
            ConnectionStateChanged();
        }

        public int LastResponseTimeMs
        {
            get => _lastResponseTimeMs;
            protected set { _lastResponseTimeMs = value; InvokePropertyChanged(); }
        }

        private void InvokePropertyChanged([CallerMemberName] string name = null)
            => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));


        internal MagicProxyClientBase()
        {
            var type = MagicProxyHelper.CompileProxy<TInterface>();
            var proxy = Activator.CreateInstance(type);
            ((MagicProxyBase)proxy).MagicDispatcher = this;
            Proxy = (TInterface)proxy;
            MethodTable = MagicProxyHelper.ReadInterfaceMethods<TInterface, MethodEntry>();
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

        protected abstract Task<(string, byte[])> DoRequestImpl(string request);

        Task<(string, byte[])> IMagicDispatcher.DoRequest(string method, JArray tArgs, JArray args)
        {
            var required = MethodTable[method].RequiredFlags;
            var missing = required & ~_connectionStateUint;
            if (missing > 0) throw new Exception($"Method [{method}] is not allowed, state(s) missing: [{Enum.ToObject(typeof(TConnectionState), missing)}]");
            var request = new JArray(method, tArgs, args).ToString(Formatting.None);
            return DoRequestImpl(request);
        }
    }

    public sealed class MagicProxyClient<TInterface, TConnectionState>
        : MagicProxyClientBase<TInterface, TConnectionState>, IMagicConnection<TInterface, TConnectionState>
        where TInterface : class
    {
        private readonly bool _useSsl;
        private readonly int _port;
        private readonly string _hostname;
        private readonly X509Certificate2 _serverCaCert;
        private readonly X509Certificate2 _clientPrivCert;

        private Stream _dataStream;
        private SslStream _sslStream;
        private TcpClient _tcpClient;

        /// <param name="serverCaCert">If null, MagicProxy uses a plaintext TCP connection</param>
        /// <param name="clientPrivCert">If null, the client does not authenticate using a client certificate</param>
        public MagicProxyClient(string hostname, int port, X509Certificate2 serverCaCert = null, X509Certificate2 clientPrivCert = null)
        {
            _hostname = hostname;
            _port = port;

            if (serverCaCert != null)
            {
                _useSsl = true;
                _serverCaCert = serverCaCert;
                if (clientPrivCert != null)
                {
                    _clientPrivCert = clientPrivCert.HasPrivateKey
                        ? clientPrivCert
                        : throw new ArgumentException("client certificate need private key");
                }
            }
        }

        public override async Task ConnectAsync()
        {
            if (Connected) return;

            _tcpClient = new TcpClient();
            await _tcpClient.ConnectAsync(_hostname, _port).ConfigureAwait(false);
            var tcpStream = _tcpClient.GetStream();

            if (_useSsl)
            {
                _sslStream = new SslStream(tcpStream, false, ValidateServerCertificate, null, EncryptionPolicy.RequireEncryption);
                var clientCerts = _clientPrivCert == null ? null : new X509CertificateCollection(new[] { _clientPrivCert });
                await _sslStream.AuthenticateAsClientAsync(_hostname, clientCerts, false).ConfigureAwait(false);
                if (!_sslStream.IsSigned || !_sslStream.IsEncrypted) throw new Exception("Non secure connection");
            }

            _dataStream = _useSsl ? (Stream)_sslStream : tcpStream;
            var (succ, connState, errBytes, _) = await _dataStream.ReadMessageAsync(CancellationToken.None).ConfigureAwait(false);
            if (!succ) throw new Exception("server did not answer connect with initial state update");
            HandleConnectionStateUpdate(connState);
            if (errBytes?.Length > 0) throw new Exception(Encoding.UTF8.GetString(errBytes));

            Connected = true;
        }

        public override async Task DisconnectAsync()
        {
            if (!Connected || _dataStream == null) return;
            try
            {
                if (_useSsl) await _sslStream.ShutdownAsync().ConfigureAwait(false);
                _tcpClient?.Close();
            }
            catch (Exception) { }
            Connected = false;
        }

        private Task<(bool, uint, byte[], byte[])> QueryServerSafely(uint clientState, byte[] reqBytes) =>
            RunQuerySequentially(async () =>
            {
                await _dataStream.WriteMessageAsync(clientState, null, reqBytes, CancellationToken.None).ConfigureAwait(false);
                var result = await _dataStream.ReadMessageAsync(CancellationToken.None).ConfigureAwait(false);
                var (readSuccessful, connectionState, _, _) = result;
                if (readSuccessful) HandleConnectionStateUpdate(connectionState);
                return result;
            });

        protected override async Task<(string, byte[])> DoRequestImpl(string request)
        {
            var requestBytes = Encoding.UTF8.GetBytes(request);
            var (success, _, err, resp) = await QueryServerSafely(0, requestBytes).ConfigureAwait(false);
            if (!success) throw new Exception("No response from server");
            var errString = err.Length > 0 ? Encoding.UTF8.GetString(err) : null;
            return (errString, resp);
        }

        private bool ValidateServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            if (_serverCaCert == null) return true;
            return MagicProxyHelper.VerifyChainWithCa(chain, sslPolicyErrors, _serverCaCert);
        }
    }
}