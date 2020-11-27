using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json.Serialization;

namespace Yoq.MagicProxy.Test
{
    [TestClass]
    public class ProxyCompilerTest
    {
        [TestMethod]
        public async Task Test()
        {
            var obj = MagicCompiledProxy.GenerateProxy<ITest>(null);
            try
            {
                await obj.Foo(99);
            }
            catch (Exception e)
            {

            }
        }
    }

    public interface ISimple
    {
        string Barbar(int n);
    }

    public interface ITest
    {
        Task ArrTest<TIn>(TIn[] arr, TIn[,] arr2, TIn[][] arr3);
        Task<string> Foo(int bar);

        Task<TRet> FooGen<TRet, Tin>(string arg1, List<string> arg2, List<Tin> arg3, List<List<Tin>> arg4, Tin[] foo)
            where TRet : Tin
            where Tin : class, new();
    }

    public class TestImpl : ITest
    {
        public Task ArrTest<TIn>(TIn[] arr, TIn[,] arr2, TIn[][] arr3)
        {
            throw new NotImplementedException();
        }

        public Task<string> Foo(int bar)
        {
            throw new NotImplementedException();
        }

        public Task<TRet> FooGen<TRet, Tin>(string arg1, List<string> arg2, List<Tin> arg3, List<List<Tin>> arg4, Tin[] foo)
            where TRet : Tin
            where Tin : class, new()
        {
            throw new NotImplementedException();
        }
    }
}
