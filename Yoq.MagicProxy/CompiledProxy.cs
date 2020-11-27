using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Reflection.Emit;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Yoq.MagicProxy
{
    internal interface IMagicProxyClient
    {
        Task<(string, byte[])> RemoteRequest(string method, JArray tArgs, JArray args);
    }

    public abstract class MagicCompiledProxy
    {
        internal IMagicProxyClient MagicProxyClient;

        protected internal JArray Params(params object[] args)
             => new JArray(args.Select(a => a == null ? null : JToken.FromObject(a, MagicProxySettings.Serializer)).ToArray<object>());

        protected internal async Task<TReturn> RequestInternal<TReturn>(string method, JArray tArgs, JArray jArgs)
        {
            if (MagicProxyClient == null)
                throw new Exception("MagicCompiledProxy must not be used before setting MagicProxyClient");

            var (err, respData) = await MagicProxyClient.RemoteRequest(method, tArgs, jArgs).ConfigureAwait(false);
            if (err != null) throw new ServerSideException(err);

            return typeof(TReturn) == typeof(byte[])
                ? (TReturn)(object)respData
                : JsonConvert.DeserializeObject<TReturn>(Encoding.UTF8.GetString(respData), MagicProxySettings.SerializerSettings);
        }

        internal static TInterface GenerateProxy<TInterface>(IMagicProxyClient client)
        {
            var type = BuildProxyClass<TInterface>();
            var instance = Activator.CreateInstance(type);
            ((MagicCompiledProxy)instance).MagicProxyClient = client;
            return (TInterface)instance;
        }

        internal static Type BuildProxyClass<TInterface>()
        {
            var typeSignature = $"CompiledProxy_{typeof(TInterface).Name}";
            var an = new AssemblyName(typeSignature);
            var assemblyBuilder = AppDomain.CurrentDomain.DefineDynamicAssembly(an, AssemblyBuilderAccess.Run); // | AssemblyBuilderAccess.Save);
            var moduleBuilder = assemblyBuilder.DefineDynamicModule("MainModule");//, "dyn.dll");
            var tb = moduleBuilder.DefineType(typeSignature,
                TypeAttributes.Public |
                TypeAttributes.Class |
                TypeAttributes.BeforeFieldInit, typeof(MagicCompiledProxy));

            var ifType = typeof(TInterface);
            tb.AddInterfaceImplementation(ifType);
            tb.DefineDefaultConstructor(MethodAttributes.Public | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName);

            var methods = ifType.GetMethods();
            foreach (var mi in methods)
            {
                var method = tb.DefineMethod(mi.Name, MethodAttributes.Public | MethodAttributes.HideBySig | MethodAttributes.Virtual | MethodAttributes.NewSlot);
                if (mi.ContainsGenericParameters)
                {
                    var inGenArgs = mi.GetGenericArguments();
                    var genBuilders = method.DefineGenericParameters(inGenArgs.Select(g => g.Name).ToArray());
                    for (var n = 0; n < inGenArgs.Length; n++)
                    {
                        var inGenArg = inGenArgs[n];
                        var genArgBuilder = genBuilders[n];
                        genArgBuilder.SetGenericParameterAttributes(inGenArg.GenericParameterAttributes);
                        var typeConstraints = inGenArg.GetGenericParameterConstraints()
                            .Select(tc => SwapInGenericParams(tc, genBuilders))
                            .ToList();

                        var ifConstraints = typeConstraints.Where(t => t.IsInterface).ToArray();
                        if (ifConstraints.Length > 0) genArgBuilder.SetInterfaceConstraints(ifConstraints);
                        var baseConstraint = typeConstraints.Except(ifConstraints).SingleOrDefault();
                        if (baseConstraint != null) genArgBuilder.SetBaseTypeConstraint(baseConstraint);
                    }
                    method.SetReturnType(SwapInGenericParams(mi.ReturnType, genBuilders));
                    var swappedParams = mi.GetParameters()
                        .Select(p => SwapInGenericParams(p.ParameterType, genBuilders))
                        .ToArray();
                    if (swappedParams.Length > 0) method.SetParameters(swappedParams);
                    WriteIl(method.GetILGenerator(), mi, genBuilders);
                }
                else
                {
                    method.SetReturnType(mi.ReturnType);
                    method.SetParameters(mi.GetParameters().Select(p => p.ParameterType).ToArray());
                    WriteIl(method.GetILGenerator(), mi, new GenericTypeParameterBuilder[0]);
                }
            }
            //assemblyBuilder.Save("dyn.dll");
            return tb.CreateType();
        }

        private static Type SwapInGenericParams(Type target, GenericTypeParameterBuilder[] genericTypes)
        {
            if (!target.ContainsGenericParameters) return target;
            if (target.IsGenericParameter) return genericTypes[target.GenericParameterPosition];
            if (target.IsArray)
            {
                var arrType = SwapInGenericParams(target.GetElementType(), genericTypes);
                var rank = target.GetArrayRank();
                return rank == 1 ? arrType.MakeArrayType() : arrType.MakeArrayType(rank);
            }
            var genericTypeDefinition = target.GetGenericTypeDefinition();
            var typeArgs = target.GenericTypeArguments.Select(ta => SwapInGenericParams(ta, genericTypes)).ToArray();
            return genericTypeDefinition.MakeGenericType(typeArgs);
        }

        private static void WriteIl(ILGenerator gen, MethodInfo mi, GenericTypeParameterBuilder[] genericTypeArgs)
        {
            var parameters = mi.GetParameters();

            gen.Emit(OpCodes.Ldarg_0);//base.RequestInternal<TRet>(this, "MethodName", JArray typeArgs, JArray args)
            gen.Emit(OpCodes.Ldstr, mi.Name);

            gen.Emit(OpCodes.Ldarg_0); //base.Params(this, object[])
            gen.Emit(OpCodes.Ldc_I4_S, (byte)genericTypeArgs.Length);
            gen.Emit(OpCodes.Newarr, typeof(object)); //new object[genericTypeArgs.Length]
            for (var n = 0; n < genericTypeArgs.Length; n++)
            {
                gen.Emit(OpCodes.Dup);
                gen.Emit(OpCodes.Ldc_I4_S, n);
                gen.Emit(OpCodes.Ldtoken, genericTypeArgs[n]);
                gen.Emit(OpCodes.Call, GetTypeFromHandleFn); //typeof(Tn)
                gen.Emit(OpCodes.Callvirt, FullNameGetter);
                gen.Emit(OpCodes.Stelem_Ref); //arr[idx]=obj, pops all 3 from stack
            }
            gen.Emit(OpCodes.Call, ParamsFn);

            gen.Emit(OpCodes.Ldarg_0); //base.Params(this, object[])
            gen.Emit(OpCodes.Ldc_I4_S, (byte)parameters.Length);
            gen.Emit(OpCodes.Newarr, typeof(object)); //new object[parameters.Length]
            for (var n = 0; n < parameters.Length; n++)
            {
                gen.Emit(OpCodes.Dup);
                gen.Emit(OpCodes.Ldc_I4_S, n);
                gen.Emit(OpCodes.Ldarg_S, n + 1); //arg0 = this

                //box value types before adding to object[] array
                if (parameters[n].ParameterType.IsValueType)
                    gen.Emit(OpCodes.Box, parameters[n].ParameterType);

                gen.Emit(OpCodes.Stelem_Ref);
            }
            gen.Emit(OpCodes.Call, ParamsFn);

            var internalRetTypeArg = mi.ReturnType == typeof(Task)
                ? typeof(int)
                : mi.ReturnType.GenericTypeArguments[0];

            //gen.Emit(OpCodes.Tailcall); //hide compiled stack frame (small performance penalty)
            gen.Emit(OpCodes.Call, RequestInternalFn.MakeGenericMethod(internalRetTypeArg));
            gen.Emit(OpCodes.Ret);
        }

        private static readonly MethodInfo FullNameGetter = typeof(Type).GetProperty(nameof(Type.FullName)).GetMethod;
        private static readonly MethodInfo GetTypeFromHandleFn = typeof(Type).GetMethod(nameof(Type.GetTypeFromHandle));
        private static readonly MethodInfo ParamsFn = typeof(MagicCompiledProxy).GetMethod(nameof(MagicCompiledProxy.Params), BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
        private static readonly MethodInfo RequestInternalFn = typeof(MagicCompiledProxy).GetMethod(nameof(MagicCompiledProxy.RequestInternal), BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
    }
}
