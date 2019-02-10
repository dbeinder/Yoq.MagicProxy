using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Yoq.MagicProxy
{
    public interface IMagicConnection : INotifyPropertyChanged
    {
        bool Busy { get; }
        bool Connected { get; }
        bool Authenticated { get; }
        Task ConnectAsync();
        Task DisconnectAsync();
    }

    public interface IMagicConnection<out TIPublic, out TIAuthenticated> : IMagicConnection
    {
        TIPublic PublicProxy { get; }
        TIAuthenticated AuthenticatedProxy { get; }
    }

    public class ServerSideException : Exception
    {
        public ServerSideException(string message) : base(message) { }
    }

    public enum MagicMethodType
    {
        Normal,
        Authenticate,
        CancelAuthentication
    }

    public class MagicMethodAttribute : Attribute
    {
        public MagicMethodType MethodType;
        public MagicMethodAttribute(MagicMethodType type) => MethodType = type;
    }
}
