using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Security;
using System.Reflection;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
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

            if (ca == null) throw new AuthenticationException($"No CA!");
            if (chain == null || chain.ChainElements.Count == 0) throw new AuthenticationException($"Empty Chain [{chain?.ChainElements?.Count}]");

            var clientCert = chain.ChainElements[0].Certificate;
            var intermediates = new X509Certificate2[chain.ChainElements.Count - 1];
            for (var n = 1; n < chain.ChainElements.Count; n++) intermediates[n - 1] = chain.ChainElements[n].Certificate;

            //verify custom CA
            return Utility.VerifyCert(clientCert, true, X509RevocationMode.NoCheck, ca, intermediates);
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
                populateAction?.Invoke(me);

            return methods;
        }
    }
}
