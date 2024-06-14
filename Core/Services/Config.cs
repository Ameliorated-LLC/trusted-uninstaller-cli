using System;
using System.Collections.Concurrent;
using System.Globalization;
using System.Runtime.Serialization;
using System.Threading;
using System.Xml;
using System.Xml.Serialization;
using Interprocess;

namespace Core
{
    /* TODO: Interprocess Config
    [Serializable]
    public class InterConfigObject<TType> : ISerializable
    {
        private TType _localValue;
        private string _name;
        public InterConfigObject(TType value, string name) => (_localValue, _name) = (value, name);

        public void Set(TType value)
        {
            _localValue = value;
        }
        public TType Get()
        {
            return _localValue;
        }

        protected InterConfigObject(SerializationInfo info, StreamingContext context)
        {
            _localValue = (TType)info.GetValue(_name, typeof(TType));
        }

        public void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            info.AddValue(_name, _localValue);
        }
    }

    public class WizardConfig
    {
        public InterConfigObject<string> VersionString = new InterConfigObject<string>("0.7.5", nameof(VersionString));
    }
    public static class Config
    {
        private static Thread _configThread = null;
        private static CancellationTokenSource _configThreadCancel = null;
        private static readonly BlockingCollection<InterConfigObject> Queue = new BlockingCollection<InterConfigObject>();

        private static object _lockObject = new object();
        public static Level Host;
        public static bool IsHost;
        public static bool IsWriter;

        private static void StartConfigThread(Level host, bool writer)
        {
            lock (_lockObject)
            {
                if (_configThread != null)
                    throw new Exception("Only one logging instance allowed.");

                Host = host;
                IsHost = host == InterLink.ApplicationLevel.ToLevel();
                IsWriter = writer;

                _configThreadCancel = new CancellationTokenSource();
                _configThread = new Thread(ThreadLoop) { IsBackground = true, CurrentUICulture = CultureInfo.InvariantCulture };
                _configThread.Start();
            }
        }

        private static void EndConfigThread()
        {
            lock (_lockObject)
            {
                _configThreadCancel.Cancel();
                if (!_configThread.Join(2000))
                    throw new TimeoutException("Log thread took too long to exit.");

                _configThread = null;
            }
        }

        private static void ThreadLoop()
        {
            foreach (var message in Queue.GetConsumingEnumerable(_configThreadCancel.Token))
            {
                if (IsWriter)
                {
                    try
                    {
                        XmlSerializer serializer = new XmlSerializer(typeof(Config));
                        using (XmlWriter writer = XmlWriter.Create(ConfigPath, new XmlWriterSettings() {Indent = true}))
                        {
                            serializer.Serialize(writer, Current);
                        }
                    }
                    catch (Exception e) { Log.EnqueueExceptionSafe(e); }
                }
                if (!IsHost)
                {
                    InterLink.ExecuteSafe()
                }
                Wrap.ExecuteSafe(() => Write(message));
            }
        }

          */
}
