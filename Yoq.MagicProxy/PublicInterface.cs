using System;
using System.ComponentModel;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace Yoq.MagicProxy
{
    public interface IMagicInterfaceImpl<TConnectionState> where TConnectionState : unmanaged, Enum
    {
        /// <summary>Validate an incoming connection, return string to decline with message, or null to accept</summary>
        Task<string> ApproveConnection();

        /// <summary>The TConnectionState flags enum MUST be UInt32. Changes are pushed to the client with every call</summary>
        TConnectionState ConnectionState { get; }
        internal unsafe UInt32 ConnectionStateUInt { get { var val = ConnectionState; return *(uint*)(&val); } }

        /// <summary>The remote endpoint of the connected client</summary>
        EndPoint RemoteEndPoint { get; set; }

        /// <summary>The certificate of the connected client</summary>
        X509Certificate2 ClientCertificate { get; set; }

        /// <summary>Used only for logging by MagicProxy</summary>
        string ConnectionId { get; }
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
}
