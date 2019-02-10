using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Newtonsoft.Json.Serialization;

namespace Yoq.MagicProxy.Test
{
    [TestClass]
    public class SerializeTest
    {
        [TestMethod]
        public void Test()
        {
            MagicProxySettings.TypeSearchAssemblies.Add(typeof(LolClass).Assembly);

            var impl = new FullBackendImpl();
            var mock = new MagicProxyMockConnection<IPublicBackend, PublicBackendProxy, ISecuredBackend, SecuredBackendProxy>(impl, impl);

            //display line data
            mock.WireSniffer = (req, err, resp) =>
                 {
                     Console.Write(req + " => ");
                     Console.WriteLine(err == null ? Encoding.UTF8.GetString(resp) : $"err: {err}");
                 };
            mock.ConnectAsync().Wait();
            mock.PublicProxy.Authenticate("foo", "bar").Wait();
            var proxy = mock.AuthenticatedProxy;

            proxy.SimpleAction().Wait();
            proxy.DoBar(11).Wait();
            var ret = proxy.Foo(42).Result;
            var raw = proxy.GetRaw().Result;
            var aa = proxy.GetFromDb<Guid>(123).Result;
            var bb = proxy.GetFromDb<LolClass>(123).Result;
            bb.Member = "aBC";
            proxy.Update(bb).Wait();
            var nst = proxy.Nested<LolClass>().Result;
            var der = proxy.Nested<LolDerived>().Result;
            Assert.ThrowsExceptionAsync<ServerSideException>(() => proxy.SimpleThrows()).Wait();

            Console.WriteLine("\nBenchmark...");
            mock.WireSniffer = null;
            const int cnt = 100000;
            var sw = new Stopwatch();
            sw.Start();
            for (var n = cnt; n >= 0; n--) proxy.Foo(n).Wait();
            sw.Stop();
            Console.WriteLine($"{cnt / sw.Elapsed.TotalSeconds:F0} ops per second");
            Console.WriteLine($"{1000d * sw.ElapsedMilliseconds / cnt:F1}us per op");
        }
    }
}
