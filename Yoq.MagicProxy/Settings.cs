using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using System.Web.Configuration;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Yoq.MagicProxy
{
    public static class MagicProxySettings
    {
        public static int MaxMessageSize = 20 * 1024 * 1024;
        public static IList<Assembly> TypeSearchAssemblies { get; } = new List<Assembly>();

        private static JsonSerializerSettings _serializerSettings = new JsonSerializerSettings
        {
            TypeNameHandling = TypeNameHandling.None,
            DateFormatHandling = DateFormatHandling.IsoDateFormat,
            DateTimeZoneHandling = DateTimeZoneHandling.RoundtripKind,
            DateParseHandling = DateParseHandling.DateTimeOffset
        };
        public static JsonSerializerSettings SerializerSettings
        {
            get => _serializerSettings;
            set { _serializerSettings = value; Serializer = JsonSerializer.Create(value); }
        }

        internal static JsonSerializer Serializer = JsonSerializer.Create(SerializerSettings);
        
        internal static void CheckInterface<TInterface>()
        {
            var ifType = typeof(TInterface);
            if (!ifType.IsInterface) throw new ArgumentException($"{ifType.Name} must be an interface!");
            var overloads = ifType
                .GetMethods().GroupBy(m => m.Name)
                .Where(g => g.Count() > 1).Select(g => g.Key)
                .ToList();
            if (overloads.Count > 0)
                throw new ArgumentException($"{ifType.Name} contains overloads: {string.Join(", ", overloads)}");

            var withAttribute = ifType.GetMethods()
                .Select(m => (Method: m, Attr: m.GetCustomAttribute<MagicMethodAttribute>()))
                .Where(q => q.Attr != null);

            foreach (var info in withAttribute)
            {
                switch (info.Attr.MethodType)
                {
                    case MagicMethodType.Normal: break;
                    case MagicMethodType.Authenticate:
                        if(info.Method.ReturnType != typeof(Task<bool>)) 
                            throw new ArgumentException($"Authenticate method {info.Method.Name}() must return bool");
                        break;
                }
            }
        }
    }
}
