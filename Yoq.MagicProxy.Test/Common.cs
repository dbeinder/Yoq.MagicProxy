using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace Yoq.MagicProxy.Test
{
    [Flags]
    public enum ConnectionFlags : uint
    {
        None = 0,
        ClientVersionOk = 0x01,
        ClientCertOk = 0x02,
        LoggedIn = 0x04
    }

    [DefaultRequiredFlags(ConnectionFlags.ClientVersionOk | ConnectionFlags.ClientCertOk | ConnectionFlags.LoggedIn)]
    public interface IBackend
    {
        [RequiredFlags(ConnectionFlags.ClientCertOk)]
        Task<bool> ClientUpdateRequired(int clientVersion);

        [RequiredFlags(ConnectionFlags.ClientCertOk | ConnectionFlags.ClientVersionOk)]
        Task<bool> Authenticate(string user, string password);

        Task Logout();

        [RequiredFlags(ConnectionFlags.None)]
        Task<double> Foo(int x); //fully public

        Task SimpleAction();
        Task SimpleThrows();
        Task<DateTimeOffset> DateTest(DateTime dt, DateTimeOffset dto);
        Task DoBar(int x);
        Task<byte[]> GetRaw(int count);
        Task Update<T>(T data);
        Task<T> GetFromDb<T>(int y) where T : new();
        Task<T> GetNull<T>();
        Task<List<T>> Nested<T>() where T : new();

    }

    public class LolClass { public string Member = "FooBar"; }
    public class LolDerived : LolClass { public string AddlMember = "FFFXX"; }
    
    public class FullBackendImpl : IBackend, IMagicInterfaceImpl<ConnectionFlags>
    {
        protected ConnectionFlags ConnectionState = ConnectionFlags.None;
        public uint ConnectionStateUInt => (uint)ConnectionState;
        public EndPoint RemoteEndPoint { get; set; }
        public X509Certificate2 ClientCertificate { get; set; }

        private readonly object _lock = new object();
        public double Count = 0;

        public Task SimpleAction() => Task.CompletedTask;
        public Task SimpleThrows() => throw new AccessViolationException("server side failure!");
        public Task<DateTimeOffset> DateTest(DateTime dt, DateTimeOffset dto)
        {
            return Task.FromResult(dto);
        }

        public Task DoBar(int x) => Task.CompletedTask;

        public Task<double> Foo(int x)
        {
            lock (_lock)
                return Task.FromResult(Count++ * x * 277.2);
        }

        public Task<byte[]> GetRaw(int count)
        {
            var buffer = new byte[count];
            if (count > 0) buffer[0] = 0x55;
            if (count > 1) buffer[count - 1] = 0x66;
            return Task.FromResult(buffer);
        }

        public Task Update<T>(T data) => Task.CompletedTask;
        public Task<T> GetFromDb<T>(int y) where T : new() => Task.FromResult(new T());
        public Task<T> GetNull<T>() => Task.FromResult(default(T));
        public Task<List<T>> Nested<T>() where T : new() => Task.FromResult(new List<T>() { new T(), new T() });

        public Task<bool> ClientUpdateRequired(int clientVersion)
        {
            var updateRequired = clientVersion != 77;
            ConnectionState = (ConnectionState & ~ConnectionFlags.ClientVersionOk) |
                              (!updateRequired ? ConnectionFlags.ClientVersionOk : 0);
            return Task.FromResult(updateRequired);
        }

        public Task<bool> Authenticate(string user, string password)
        {
            var goodLogin = user == "foo" && password == "bar";
            ConnectionState = (ConnectionState & ~ConnectionFlags.LoggedIn) |
                              (goodLogin ? ConnectionFlags.LoggedIn : 0);
            return Task.FromResult(goodLogin);
        }

        public Task<string> ApproveConnection()
        {
            string error = null;
            if (ClientCertificate == null)
                error = "No client cert [FullBackendImpl]";
            else
                ConnectionState |= ConnectionFlags.ClientCertOk;

            return Task.FromResult(error);
        }

        public Task Logout() => Task.FromResult(ConnectionFlags.None);
    }
}
