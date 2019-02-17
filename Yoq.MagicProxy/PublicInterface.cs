using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace Yoq.MagicProxy
{
    public interface IMagicBackendImpl<TConnectionState>
    {
        /// <summary>return string to decline with message, or null to accept</summary>
        Task<string> ValidateConnection();
        uint ConnectionStateUInt { get; }
        EndPoint RemoteEndPoint { get; set; }
        X509Certificate2 ClientCertificate { get; set; }
    }

    public interface IMagicConnection : INotifyPropertyChanged
    {
        bool Busy { get; }
        bool Connected { get; }
        int LastResponseTimeMs { get; }
        Task ConnectAsync();
        Task DisconnectAsync();
    }

    public interface IMagicConnection<out TInterface, out TConnectionState> : IMagicConnection
    {
        TInterface Proxy { get; }
        TConnectionState ConnectionState { get; }
    }

    public class ServerSideException : Exception
    {
        public ServerSideException(string message) : base(message) { }
    }

    [AttributeUsage(AttributeTargets.Method)]
    public class RequiredFlagsAttribute : Attribute
    {
        public uint RequiresFlags;
        public RequiredFlagsAttribute(object flags) => RequiresFlags = Convert.ToUInt32(flags);
    }
    
    [AttributeUsage(AttributeTargets.Interface)]
    public class DefaultRequiredFlagsAttribute : Attribute
    {
        public uint RequiresFlags;
        public DefaultRequiredFlagsAttribute(object flags) => RequiresFlags = Convert.ToUInt32(flags);
    }

    [AttributeUsage(AttributeTargets.Method)]
    public class SetsFlagsAttribute : Attribute
    {
        public uint SetterMask;
        public SetsFlagsAttribute(object setterMask) => SetterMask = Convert.ToUInt32(setterMask);
    }
}
