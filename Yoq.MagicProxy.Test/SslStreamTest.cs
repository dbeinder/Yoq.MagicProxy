using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Newtonsoft.Json.Serialization;

namespace Yoq.MagicProxy.Test
{
    [TestClass]
    public class SslStreamTest
    {
        private static int _port = 8085;
        private static readonly X509Certificate2 _pubKey = ReadEmbedded("pub.cert");
        private static readonly X509Certificate2 _privKey = ReadEmbedded("priv.cert");

        private static X509Certificate2 ReadEmbedded(string filename)
        {
            var resourceName = typeof(ServerClientTest).Namespace + "." + filename;
            using (var stream = typeof(ServerClientTest).Assembly.GetManifestResourceStream(resourceName))
            using (var memStream = new MemoryStream())
            {
                stream.CopyTo(memStream);
                return new X509Certificate2(memStream.ToArray());
            }
        }

        [TestMethod]
        public async Task Test()
        {
            var impl = new FullBackendImpl();
            var server = new Server(_port, _privKey);
            var client = new Client("localhost", _port, _pubKey);

            server.StartServer();
            Thread.Sleep(100);
            await client.ConnectAsync();
            await Task.Delay(100);
            await client.Query();
        }
    }

    public sealed class Client
    {
        private readonly int _port;
        private readonly string _server;
        private readonly X509Certificate2 _caCert;

        private SslStream _sslStream;
        private TcpClient _tcpClient;

        public Client(string server, int port, X509Certificate2 pubCert)
        {
            _server = server;
            _port = port;
            _caCert = pubCert;
        }

        public async Task ConnectAsync()
        {
            var commonName = _caCert.GetNameInfo(X509NameType.SimpleName, false);
            _tcpClient = new TcpClient();
            await _tcpClient.ConnectAsync(_server, _port).ConfigureAwait(false);
            _sslStream = new SslStream(_tcpClient.GetStream(), false, ValidateServerCertificate, null);
            await _sslStream.AuthenticateAsClientAsync(commonName).ConfigureAwait(false);
        }

        public async Task Query()
        {
            var buffer = new byte[1024 * 1024];
            buffer[0] = 0x11;
            buffer[1] = 0x12;
            buffer[2] = 0x13;
            buffer[3] = 0x14;
            buffer[buffer.Length - 1] = 0x55;
            await _sslStream.WriteAsync(buffer, 0, buffer.Length);
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

    public sealed class Server
    {

        private readonly X509Certificate2 _serverCertificate;
        private readonly int _port;

        private CancellationTokenSource _cancelSource;

        public Server(int port, X509Certificate2 privCert)
        {
            _port = port;
            _serverCertificate = privCert;
        }

        public void StartServer()
        {
            StopServer();
            _cancelSource = new CancellationTokenSource();
            Task.Factory.StartNew(ServerLoop, TaskCreationOptions.LongRunning);
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
            SslStream sslStream = null;
            var clientEndPoint = client?.Client?.RemoteEndPoint;
            try
            {
                var tcpStream = client.GetStream();
                tcpStream.ReadTimeout = 5000;
                tcpStream.WriteTimeout = 5000;

                //var bufferedStream = new BufferedStream(tcpStream, 1024 * 1024);
                sslStream = new SslStream(tcpStream, false);

                await sslStream.AuthenticateAsServerAsync(_serverCertificate, false, false).ConfigureAwait(false);
                Console.WriteLine($"[{clientEndPoint}] Client connected");

                while (true)
                {
                    var readBuffer = new byte[1024 * 1024];
                    var readCnt = await sslStream.ReadAsync(readBuffer, 0, 4);
                    if (readCnt != 4) throw new Exception();

                    var ChunkSize = 14000;
                    var pos = 4;
                    while (pos != readBuffer.Length)
                    {
                        var left = readBuffer.Length - pos;
                        //var readSize = left > ChunkSize ? ChunkSize : left;
                        readCnt = await sslStream.ReadAsync(readBuffer, pos, left, ct).ConfigureAwait(false);
                        if (readCnt == 0) throw new Exception($"{readCnt} was 0");
                        pos += readCnt;
                    }

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
                sslStream?.Close();
                client?.Close();
            }
        }
    }
}
