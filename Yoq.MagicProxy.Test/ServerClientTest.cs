using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Yoq.MagicProxy.Test
{
    [TestClass]
    public class ServerClientTest
    {
        private static int _port = 8085;
        
        /* https://www.samltool.com/self_signed_certs.php
         * λ openssl pkcs12 -export -in cert.txt -inkey pk.txt -out mycert.pfx
                Enter Export Password:
                Verifying - Enter Export Password:
         */

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
        public void Test()
        {
            MagicProxySettings.TypeSearchAssemblies.Add(typeof(LolClass).Assembly);
            var impl = new FullBackendImpl();
            var server = new MagicProxyServer<IPublicBackend, ISecuredBackend>(impl, impl, _port, _privKey);
            var proxy = new MagicProxyClient<PublicBackendProxy, SecuredBackendProxy>("localhost", _port, _pubKey);

            server.StartServer();
            Thread.Sleep(100);
            proxy.ConnectAsync().Wait();
            var connected = proxy.Connected;
            var auth = proxy.Authenticated;
            var success = proxy.PublicProxy.Authenticate("foo", "bar").Result;
            auth = proxy.Authenticated;
            proxy.AuthenticatedProxy.Logout().Wait();
            auth = proxy.Authenticated;
            success = proxy.PublicProxy.Authenticate("foo", "bar").Result;
            auth = proxy.Authenticated;

            var secureProxy = proxy.AuthenticatedProxy;
            secureProxy.SimpleAction().Wait();
            secureProxy.DoBar(11).Wait();
            var ret = secureProxy.Foo(42).Result;
            var raw = secureProxy.GetRaw().Result;
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

        private static Task ClientInstance(int cnt)
        {
            return Task.Run(async () =>
            {
                var proxy = new MagicProxyClient<PublicBackendProxy, SecuredBackendProxy>("localhost", _port, _pubKey);
                await proxy.ConnectAsync();
                await proxy.PublicProxy.Authenticate("foo", "bar");
                for (var n = cnt; n > 0; n--)
                    await proxy.AuthenticatedProxy.Foo(n);

                await proxy.DisconnectAsync();
            });
        }
    }
}
