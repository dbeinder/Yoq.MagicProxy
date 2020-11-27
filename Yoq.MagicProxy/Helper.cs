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
    internal class MethodEntry
    {
        public MethodInfo MethodInfo;
        public uint RequiredFlags;
    }

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
            if (!Utility.VerifyCert(clientCert, true, X509RevocationMode.NoCheck, ca, intermediates))
                throw new AuthenticationException("Certificate is not a valid leaf of CA");

            return true;
        }

        internal static IReadOnlyDictionary<string, T> ReadInterfaceMethods<TInterface, T>() where T : MethodEntry, new()
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
            }

            return methods;
        }
    }
}
