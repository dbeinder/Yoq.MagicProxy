using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Security;
using System.Reflection;
using System.Reflection.Emit;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using CryptLink.SigningFramework;

namespace Yoq.MagicProxy
{
    internal static class MagicProxyHelper
    {
        internal static bool VerifyChainWithCa(X509Chain chain, SslPolicyErrors sslPolicyErrors, X509Certificate2 ca)
        {
            //ignore RemoteCertificateChainErrors
            sslPolicyErrors &= ~SslPolicyErrors.RemoteCertificateChainErrors;
            if (sslPolicyErrors != SslPolicyErrors.None) throw new AuthenticationException($"Policy Errors: [{sslPolicyErrors}]");

            if (ca == null) throw new AuthenticationException($"No CA provided!");
            if (chain == null || chain.ChainElements.Count == 0) throw new AuthenticationException($"Empty Chain [{chain?.ChainElements?.Count}]");

            var clientCert = chain.ChainElements[0].Certificate;
            var intermediates = new X509Certificate2[chain.ChainElements.Count - 1];
            for (var n = 1; n < chain.ChainElements.Count; n++) intermediates[n - 1] = chain.ChainElements[n].Certificate;

            //verify custom CA
            if(!Utility.VerifyCert(clientCert, true, X509RevocationMode.NoCheck, ca, intermediates))
                throw new AuthenticationException("Certificate is not a valid leaf of CA");

            return true;
        }

        internal static Dictionary<string, T> ReadInterfaceMethods<TInterface, T>(Action<T> populateAction = null) where T : MethodEntry, new()
        {
            var ifType = typeof(TInterface);
            if (!ifType.IsInterface) throw new ArgumentException($"{ifType.Name} must be an interface!");

            var methodGroups = ifType
                .GetMethods().GroupBy(m => m.Name).ToList();

            var overloads = methodGroups
                .Where(g => g.Count() > 1).Select(g => g.Key)
                .ToList();

            if (overloads.Count > 0)
                throw new ArgumentException($"{ifType.Name} contains overloads: {string.Join(", ", overloads)}");

            var defaultFlags = ifType.GetCustomAttribute<DefaultRequiredFlagsAttribute>()?.RequiresFlags;

            var methods = methodGroups.Select(g => g.First())
                .ToDictionary(m => m.Name, m => new T
                {
                    MethodInfo = m,
                    RequiredFlags = m.GetCustomAttribute<RequiredFlagsAttribute>() is RequiredFlagsAttribute r
                        ? r.RequiresFlags
                        : defaultFlags ?? 0
                });

            foreach (var me in methods.Values)
            {
                if (!typeof(Task).IsAssignableFrom(me.MethodInfo.ReturnType))
                    throw new ArgumentException($"method {me.MethodInfo.Name} does not return Task/Task<T>");

                var invalidParams = me.MethodInfo.GetParameters()
                    .Where(p => p.ParameterType.IsByRef || p.ParameterType.IsPointer)
                    .Select(p => $"{p.ParameterType.Name} {p.Name}")
                    .ToList();

                if (invalidParams.Count > 0)
                    throw new ArgumentException($"{me.MethodInfo.Name} contains invalid ref/out/pointer parameters: {string.Join(", ", invalidParams)}");

                populateAction?.Invoke(me);
            }

            return methods;
        }

        private static int _proxyCounter = 1;
        internal static Type CompileProxy<TInterface>()
        {
            var typeSignature = "CompiledMagicProxy" + _proxyCounter++;
            var an = new AssemblyName(typeSignature);
            var assemblyBuilder = AppDomain.CurrentDomain.DefineDynamicAssembly(an, AssemblyBuilderAccess.Run); // | AssemblyBuilderAccess.Save);
            var moduleBuilder = assemblyBuilder.DefineDynamicModule("MainModule");//, "dyn.dll");
            var tb = moduleBuilder.DefineType(typeSignature,
                TypeAttributes.Public |
                TypeAttributes.Class |
                TypeAttributes.BeforeFieldInit, typeof(MagicProxyBase));

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
                gen.Emit(OpCodes.Call, GetTypeFromHandleFn);
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

            gen.Emit(OpCodes.Call, RequestInternalFn.MakeGenericMethod(internalRetTypeArg));
            gen.Emit(OpCodes.Ret);
        }

        private static readonly MethodInfo FullNameGetter = typeof(Type).GetProperty(nameof(Type.FullName)).GetMethod;
        private static readonly MethodInfo GetTypeFromHandleFn = typeof(Type).GetMethod(nameof(Type.GetTypeFromHandle));
        private static readonly MethodInfo ParamsFn = typeof(MagicProxyBase).GetMethod(nameof(MagicProxyBase.Params), BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
        private static readonly MethodInfo RequestInternalFn = typeof(MagicProxyBase).GetMethod(nameof(MagicProxyBase.RequestInternal), BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
    }
}
