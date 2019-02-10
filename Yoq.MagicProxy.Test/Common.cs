﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Yoq.MagicProxy.Test
{
    public interface IPublicBackend
    {
        [MagicMethod(MagicMethodType.Authenticate)]
        Task<bool> Authenticate(string user, string password);
    }

    public interface ISecuredBackend
    {
        Task SimpleAction();
        Task SimpleThrows();
        Task DoBar(int x);
        Task<double> Foo(int x);
        Task<byte[]> GetRaw();
        Task Update<T>(T data);
        Task<T> GetFromDb<T>(int y) where T : new();
        Task<List<T>> Nested<T>() where T : new();
    }
    
    public class LolClass { public string Member = "FooBar"; }
    public class LolDerived : LolClass { public string AddlMember = "FFFXX"; }

    public class PublicBackendProxy : MagicProxyBase, IPublicBackend
    {
        public Task<bool> Authenticate(string user, string password) => Request<bool>(Params(user, password));
    }

    public class SecuredBackendProxy : MagicProxyBase, ISecuredBackend
    {
        public Task SimpleAction() => Request(NoParams);
        public Task SimpleThrows() => Request(NoParams);
        public Task DoBar(int x) => Request(Params(x));
        public Task<double> Foo(int x) => Request<double>(Params(x));
        public Task<byte[]> GetRaw() => Request<byte[]>(NoParams);
        public Task Update<T>(T data) => RequestGeneric<T>(Params(data));
        public Task<T> GetFromDb<T>(int y) where T : new() => RequestGeneric<T, T>(Params(y));
        public Task<List<T>> Nested<T>() where T : new() => RequestGeneric<T, List<T>>(NoParams);
    }

    public class FullBackendImpl : ISecuredBackend, IPublicBackend
    {
        private readonly object _lock = new object();
        public double Count = 0;
        public Task SimpleAction() => Task.CompletedTask;
        public Task SimpleThrows() => throw new AccessViolationException("server side failure!");
        public Task DoBar(int x) => Task.CompletedTask;

        public Task<double> Foo(int x)
        {
            lock (_lock)
                return Task.FromResult(Count++ * x * 277.2);
        }

        public Task<byte[]> GetRaw() => Task.FromResult(new byte[] {0x11, 0x22, 0x33});

        public Task Update<T>(T data) => Task.CompletedTask;
        public Task<T> GetFromDb<T>(int y) where T : new() => Task.FromResult(new T());
        public Task<List<T>> Nested<T>() where T : new() => Task.FromResult(new List<T>() { new T(), new T() });

        public Task<bool> Authenticate(string user, string password) => Task.FromResult(user == "foo" && password == "bar");
    }
}