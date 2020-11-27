using System;
using System.Collections.Generic;
using System.Reflection;
using Newtonsoft.Json;

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
    }
}
