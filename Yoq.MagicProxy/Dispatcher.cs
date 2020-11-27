using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Yoq.MagicProxy
{
    internal interface IMagicDispatcher<in TInterface>
    {
        Task<(string, object)> ExecuteRequest(TInterface impl, string method, JArray tArgs, JArray args);
        byte[] SerializeResponse(object response);
    }

    //TODO: maybe move to helper? the only reason for inheriting is, it saves typing out the class name
    abstract internal class MagicDispatcherBase
    {
        protected static PropertyInfo JArrayIndexer = typeof(JArray).GetProperty("Item", typeof(JToken), new[] { typeof(int) });
        protected static MethodInfo GenericDeSerialize = typeof(MagicDispatcherBase).GetMethod(nameof(DeSerialize), BindingFlags.Static | BindingFlags.NonPublic);
        protected static MethodInfo GenericToObjectAsync = typeof(MagicDispatcherBase).GetMethod(nameof(ToObjectAsync), BindingFlags.Static | BindingFlags.NonPublic);
        protected static MethodInfo GenericToObjectAsyncVoid = typeof(MagicDispatcherBase).GetMethod(nameof(ToObjectAsyncVoid), BindingFlags.Static | BindingFlags.NonPublic);

        private static T DeSerialize<T>(JToken token) => token.ToObject<T>(MagicProxySettings.Serializer);
        private static async Task<object> ToObjectAsync<TR>(Task<TR> task) => await task.ConfigureAwait(false);
        private static async Task<object> ToObjectAsyncVoid(Task task) { await task.ConfigureAwait(false); return 0; }
    }

    internal class MagicDispatcher<TInterface> : MagicDispatcherBase, IMagicDispatcher<TInterface>
    {
        protected static readonly string LambdaPrefix = $"{typeof(MagicDispatcherBase).FullName}<{typeof(TInterface).Name}>.SerializeLambda_";

        protected delegate Task<object> CompiledLambda(TInterface b, JArray j);
        protected class DispatcherMethodEntry : MethodEntry
        {
            public CompiledLambda NonGeneric;
            public Dictionary<string, CompiledLambda> GenericLambdas = new Dictionary<string, CompiledLambda>();
        }

        protected readonly IReadOnlyDictionary<string, DispatcherMethodEntry> MethodCache;

        public MagicDispatcher()
        {
            MethodCache = MagicProxyHelper.ReadInterfaceMethods<TInterface, DispatcherMethodEntry>();
            foreach(var entry in MethodCache.Values)
            {
                entry.NonGeneric = entry.MethodInfo.IsGenericMethod ? null : BuildLambda(entry.MethodInfo);
                entry.GenericLambdas = new Dictionary<string, CompiledLambda>();
            }
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
                .Lambda<CompiledLambda>(asyncToObjectCast, LambdaPrefix + mi.Name, new[] { backendParam, argsParam })
                .Compile();
        }

        async Task<(string, object)> IMagicDispatcher<TInterface>.ExecuteRequest(TInterface impl, string method, JArray tArgs, JArray args)
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

        byte[] IMagicDispatcher<TInterface>.SerializeResponse(object response)
            => response is byte[] raw
                ? raw
                : Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(response, MagicProxySettings.SerializerSettings));
    }
}
