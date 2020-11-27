using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Common.Logging;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Yoq.MagicProxy.Test
{
    [TestClass]
    public class ServerClientTest
    {
        private static int _port = 8085;

        private static byte[] ReadEmbedded(string filename)
        {
            var resourceName = typeof(ServerClientTest).Namespace + "." + filename;
            using (var stream = typeof(ServerClientTest).Assembly.GetManifestResourceStream(resourceName))
            using (var memStream = new MemoryStream())
            {
                stream.CopyTo(memStream);
                return memStream.ToArray();
            }
        }

        [TestMethod]
        public void Test()
        {
            LogManager.Adapter = new Common.Logging.Simple.DebugLoggerFactoryAdapter(LogLevel.Info, true, true, true, "dd.MM 'UTC'z HH:mm:ss");

            var caCert = new X509Certificate2(ReadEmbedded("ca.crt"));
            var serverPrivCert = new X509Certificate2(ReadEmbedded("server.pfx"));
            var serverCerts = new[] { serverPrivCert };

            var clientCertBundle = new X509Certificate2Collection();
            clientCertBundle.Import(ReadEmbedded("client.pfx"));
            var clientPrivCert = clientCertBundle[0];

            var certStore = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            certStore.Open(OpenFlags.ReadWrite);
            for (var n = 1; n < clientCertBundle.Count; n++) certStore.Add(clientCertBundle[n]);
            certStore.Close();

            MagicProxySettings.TypeSearchAssemblies.Add(typeof(LolClass).Assembly);

            var logger = LogManager.GetLogger("ProxyServer");

            var impl = new FullBackendImpl();
            var server = new MagicProxyServer<IBackend, FullBackendImpl, ConnectionFlags>(() => impl, new IPEndPoint(IPAddress.Any, _port), logger, serverCerts, caCert);
            var client = new MagicProxyClient<IBackend, ConnectionFlags>("localhost", _port, caCert, clientPrivCert);

            server.StartServer();
            Thread.Sleep(100);
            client.ConnectAsync().Wait();
            var connected = client.Connected;
            var state0 = client.ConnectionState;
            client.Proxy.ClientUpdateRequired(77).Wait();
            var state1 = client.ConnectionState;
            client.Proxy.ClientUpdateRequired(717).Wait();
            var state2 = client.ConnectionState;
            client.Proxy.ClientUpdateRequired(77).Wait();
            var state3 = client.ConnectionState;

            var success = client.Proxy.Authenticate("foo", "bar").Result;
            var state4 = client.ConnectionState;
            client.Proxy.Logout().Wait();
            var state5 = client.ConnectionState;
            success = client.Proxy.Authenticate("foo", "bar").Result;
            var state6 = client.ConnectionState;

            var secureProxy = client.Proxy;
            secureProxy.SimpleAction().Wait();
            secureProxy.DoBar(11).Wait();
            var ret = secureProxy.Foo(42).Result;

            var raw = secureProxy.GetRaw(0x5000).Result;
            Assert.AreEqual(raw[0], 0x55);
            Assert.AreEqual(raw[0x4FFF], 0x66);
            var aa = secureProxy.GetFromDb<Guid>(123).Result;
            var bb = secureProxy.GetFromDb<LolClass>(123).Result;
            bb.Member = "aBC";
            secureProxy.Update(bb).Wait();
            var nst = secureProxy.Nested<LolClass>().Result;
            var der = secureProxy.Nested<LolDerived>().Result;
            Assert.ThrowsExceptionAsync<ServerSideException>(() => secureProxy.SimpleThrows()).Wait();

            impl.Count = 0;
            Console.WriteLine("\nBenchmark...");
            const int cnt = 10000;
            var sw = new Stopwatch();
            sw.Start();
            for (var n = cnt; n > 0; n--) secureProxy.Foo(n).Wait();
            sw.Stop();
            Console.WriteLine($"{cnt / sw.Elapsed.TotalSeconds:F0} ops per second");
            Console.WriteLine($"{1000d * sw.ElapsedMilliseconds / cnt:F1}us per op");

            Console.WriteLine(impl.Count);
            impl.Count = 0;


            sw.Restart();
            for (var n = 10; n > 0; n--) secureProxy.GetRaw(10 * 1024 * 1024).Wait();
            sw.Stop();
            Console.WriteLine($"{100d / sw.Elapsed.TotalSeconds:F0} MB/s");

            Task ClientInstance(int repeats)
            {
                return Task.Run(async () =>
                {
                    var proxy = new MagicProxyClient<IBackend, ConnectionFlags>("localhost", _port, caCert, clientPrivCert);
                    await proxy.ConnectAsync();
                    for (var n = repeats; n > 0; n--)
                        await proxy.Proxy.Foo(n);

                    await proxy.DisconnectAsync();
                });
            }

            var para = 10;
            Console.WriteLine($"\n{para} parallel clients...");
            sw.Restart();
            var tasks = Enumerable.Repeat(1, 10).Select(_ => ClientInstance(cnt)).ToArray();
            Task.WaitAll(tasks);
            sw.Stop();
            Console.WriteLine($"{para * cnt / sw.Elapsed.TotalSeconds:F0} ops per second");
            Console.WriteLine($"{1000d * sw.ElapsedMilliseconds / cnt / para:F1}us per op");

            Console.WriteLine(impl.Count);
        }
    }
}
