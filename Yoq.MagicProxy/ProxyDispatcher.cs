using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Linq.Expressions;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;
using System.Web.UI.WebControls;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Yoq.MagicProxy
{
    public abstract class MagicProxyBase
    {
        internal IMagicDispatcher MagicDispatcher;

        protected Task Request(JArray jArgs, [CallerMemberName]string method = "")
            => RequestInternal<int>(method, NoParams, jArgs);

        protected Task<TReturn> Request<TReturn>(JArray jArgs, [CallerMemberName]string method = "")
            => RequestInternal<TReturn>(method, NoParams, jArgs);


        protected Task RequestGeneric<TGeneric>(JArray jArgs, [CallerMemberName]string method = "")
            => RequestInternal<int>(method, Params(typeof(TGeneric).FullName), jArgs);

        protected Task<TReturn> RequestGeneric<TGeneric, TReturn>(JArray jArgs, [CallerMemberName]string method = "")
            => RequestInternal<TReturn>(method, Params(typeof(TGeneric).FullName), jArgs);

        protected readonly JArray NoParams = new JArray();
        protected JArray Params(params object[] args)
            => new JArray(args.Select(a => a == null ? null : JToken.FromObject(a, MagicProxySettings.Serializer)).ToArray<object>());

        private async Task<TReturn> RequestInternal<TReturn>(string method, JArray tArgs, JArray jArgs)
        {
            if (MagicDispatcher == null)
                throw new Exception("MagicProxySerializer must not be used before setting up MagicProxyServer");

            var (err, respData) = await MagicDispatcher.DoRequest(method, tArgs, jArgs).ConfigureAwait(false);
            if (err != null) throw new ServerSideException(err);

            return typeof(TReturn) == typeof(byte[])
                ? (TReturn)(object)respData
                : JsonConvert.DeserializeObject<TReturn>(Encoding.UTF8.GetString(respData), MagicProxySettings.SerializerSettings);
        }
    }

    internal interface IMagicDispatcher
    {
        Task<(string, byte[])> DoRequest(string method, JArray tArgs, JArray args);
    }

    internal interface IMagicDispatcherRaw<in TInterface>
    {
        Task<(string, object)> DoRequestRaw(TInterface impl, string method, JArray tArgs, JArray args);
        byte[] Serialize(object response);
    }

    internal class MagicDispatcher
    {
        protected static PropertyInfo JArrayIndexer = typeof(JArray).GetProperty("Item", typeof(JToken), new[] { typeof(int) });
        protected static MethodInfo GenericDeSerialize = typeof(MagicDispatcher).GetMethod(nameof(DeSerialize), BindingFlags.Static | BindingFlags.NonPublic);
        protected static MethodInfo GenericToObjectAsync = typeof(MagicDispatcher).GetMethod(nameof(ToObjectAsync), BindingFlags.Static | BindingFlags.NonPublic);
        protected static MethodInfo GenericToObjectAsyncVoid = typeof(MagicDispatcher).GetMethod(nameof(ToObjectAsyncVoid), BindingFlags.Static | BindingFlags.NonPublic);

        private static T DeSerialize<T>(JToken token) => token.ToObject<T>(MagicProxySettings.Serializer);
        private static async Task<object> ToObjectAsync<TR>(Task<TR> task) => await task.ConfigureAwait(false);
        private static async Task<object> ToObjectAsyncVoid(Task task) { await task.ConfigureAwait(false); return 0; }
    }

    internal class MagicDispatcher<TInterface> : MagicDispatcher, IMagicDispatcherRaw<TInterface>
    {
        protected delegate Task<object> CompiledLambda(TInterface b, JArray j);
        protected class DispatcherMethodEntry : MethodEntry
        {
            public CompiledLambda NonGeneric;
            public Dictionary<string, CompiledLambda> GenericLambdas = new Dictionary<string, CompiledLambda>();
        }

        protected readonly Dictionary<string, DispatcherMethodEntry> MethodCache;

        public MagicDispatcher()
        {
            MethodCache = MagicProxyHelper.ReadInterfaceMethods<TInterface, DispatcherMethodEntry>(CacheBuilder);
        }

        private void CacheBuilder(DispatcherMethodEntry entry)
        {
            entry.NonGeneric = entry.MethodInfo.IsGenericMethod ? null : BuildLambda(entry.MethodInfo);
            entry.GenericLambdas = new Dictionary<string, CompiledLambda>();
        }

        private CompiledLambda BuildLambda(MethodInfo mi)
        {
            var backendParam = Expression.Parameter(typeof(TInterface), "backend");
            var argsParam = Expression.Parameter(typeof(JArray), "jArgs");

            var argTypes = mi.GetParameters().Select(p => p.ParameterType).ToList();
            var typedArgs = argTypes.Select((at, n) =>
                Expression.Call(GenericDeSerialize.MakeGenericMethod(at),
                    Expression.MakeIndex(argsParam, JArrayIndexer, new[] { Expression.Constant(n) }))).ToArray();

            var backendCall = Expression.Call(backendParam, mi, typedArgs);

            var asyncToObjectCast = (mi.ReturnType == typeof(Task))
                ? Expression.Call(GenericToObjectAsyncVoid, backendCall)
                : Expression.Call(GenericToObjectAsync.MakeGenericMethod(mi.ReturnType.GenericTypeArguments[0]),
                    backendCall);

            return Expression
                .Lambda<CompiledLambda>(asyncToObjectCast, mi.Name, new[] { backendParam, argsParam })
                .Compile();
        }

        async Task<(string, object)> IMagicDispatcherRaw<TInterface>.DoRequestRaw(TInterface impl, string method, JArray tArgs, JArray args)
        {
            object result = 0;
            string error = null;
            CompiledLambda lambda;

            if (!MethodCache.TryGetValue(method, out var methodEntry))
                throw new Exception($"method {method} not found!");
            if (tArgs.Count == 0)
                lambda = methodEntry.NonGeneric;
            else
            {
                var tKey = string.Join("|", tArgs);
                if (methodEntry.GenericLambdas.TryGetValue(tKey, out var lm))
                    lambda = lm;
                else
                {
                    var typeArgs = tArgs.Select(ts => TypeFromString(ts.ToObject<string>())).ToArray();
                    var closedMi = methodEntry.MethodInfo.MakeGenericMethod(typeArgs);
                    lambda = BuildLambda(closedMi);
                    methodEntry.GenericLambdas.Add(tKey, lambda);
                }
            }

            try
            {
                result = await lambda(impl, args).ConfigureAwait(false);
            }
            catch (Exception e)
            {
                error = e.ToString();
            }
            return (error, result);
        }

        private Type TypeFromString(string name)
        {
            var type = Type.GetType(name); //system types
            if (type != null) return type;

            type = MagicProxySettings.TypeSearchAssemblies
                .Select(a => a.GetType(name))
                .FirstOrDefault(t => t != null);

            if (type == null)
                throw new Exception($"MagicDispatcher: type {name} not found, {MagicProxySettings.TypeSearchAssemblies.Count} assemblies loaded!");

            return type;
        }

        byte[] IMagicDispatcherRaw<TInterface>.Serialize(object response)
            => response is byte[] raw
                ? raw
                : Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(response, MagicProxySettings.SerializerSettings));
    }
}
