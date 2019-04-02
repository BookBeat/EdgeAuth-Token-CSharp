using System;
using System.Text.RegularExpressions;

namespace BookBeat.Akamai.EdgeAuthToken
{
    public interface IAkamaiTokenConfig
    {
        /// <summary>
        /// UnixTimeProvider is implemented for testability
        /// </summary>
        IUnixTimeProvider UnixTimeProvider { get; set; }

        /// <summary>
        /// Gets/sets a flag that indicates whether the Acl property will be escaped before being hashed. The default behavior is to escape the value.
        /// </summary>
        /// <remarks>This flag supports the new feature in GHost 6.5 wherein the EdgeAuth 2.0 token is 
        /// validated directly against the input from query/cookie without first escaping it.</remarks>
        bool PreEscapeAcl { get; set; }

        /// <summary>
        /// Gets/sets the algorigthm to use for creating the hmac. Default value uses SHA256 based HMAC
        /// </summary>
        Algorithm TokenAlgorithm { get; set; }

        /// <summary>
        /// Gets/sets the Ip for which this token is valid
        /// </summary>
        string Ip { get; set; }

        string IpField { get; }

        /// <summary>
        /// Gets/sets the epoch time, i.e. seconds since 1/1/1970, from which the token is valid. Default value is current time
        /// </summary>
        long StartTime { get; set; }

        string StartTimeField { get; }
        long EndTime { get; set; }
        long Window { get; set; }
        string ExpirationField { get; }

        /// <summary>
        /// The access control list for which the token is valid. Example: /*
        /// </summary>
        string Acl { get; set; }

        string AclField { get; }

        /// <summary>
        /// The session identifier for single use tokens or other advanced cases
        /// </summary>
        string SessionId { get; set; }

        string SessionIdField { get; }

        /// <summary>
        /// Additional text added to the calculated token digest
        /// </summary>
        string Payload { get; set; }

        string PayloadField { get; }


        string Key { get; set; }

        /// <summary>
        /// Character used to delimit token body fields.
        /// </summary>
        char FieldDelimiter { get; set; }

        string ToString();
    }

    /// <summary>
    /// Class for setting different configuration properties for generating a token
    /// </summary>
    public class AkamaiTokenConfig : IAkamaiTokenConfig
    {
        private static readonly Regex KeyRegex = new Regex("^[a-zA-Z0-9]+$", RegexOptions.Compiled);
        
        public AkamaiTokenConfig()
        {
            TokenAlgorithm = Algorithm.HMACSHA256;
            Ip = string.Empty;
            SessionId = string.Empty;
            Payload = string.Empty;
            FieldDelimiter = '~';
        }

        /// <summary>
        /// UnixTimeProvider is implemented for testability
        /// </summary>
        public IUnixTimeProvider UnixTimeProvider { get; set; } = new UnixTimeProvider();
        
        /// <summary>
        /// Gets/sets a flag that indicates whether the Acl property will be escaped before being hashed. The default behavior is to escape the value.
        /// </summary>
        /// <remarks>This flag supports the new feature in GHost 6.5 wherein the EdgeAuth 2.0 token is 
        /// validated directly against the input from query/cookie without first escaping it.</remarks>
        public bool PreEscapeAcl { get; set; }

        /// <summary>
        /// Gets/sets the algorigthm to use for creating the hmac. Default value uses SHA256 based HMAC
        /// </summary>
        public Algorithm TokenAlgorithm { get; set; }

        /// <summary>
        /// Gets/sets the Ip for which this token is valid
        /// </summary>
        public string Ip { get; set; }

        public string IpField
        {
            get
            {
                if (string.IsNullOrEmpty(Ip))
                    return string.Empty;
                else
                    return $"ip={Ip}{FieldDelimiter}";
            }
        }

        /// <summary>
        /// Gets/sets the epoch time, i.e. seconds since 1/1/1970, from which the token is valid. Default value is current time
        /// </summary>
        public long StartTime { get; set; }

        public string StartTimeField
        {
            get
            {
                if (StartTime == 0)
                    return string.Empty;
                else
                    return $"st={StartTime}{FieldDelimiter}";
            }
        }

        /// <summary>
        /// Gets/sets the epoch time, i.e. seconds since 1/1/1970, till which the token is valid.
        /// </summary>
        private long _endTime;
        public long EndTime
        {
            get => _endTime;
            set
            {
                if (value < 0)
                    throw new ArgumentOutOfRangeException(nameof(value), "Value should be greater than 0");

                _endTime = value;
            }
        }

        /// <summary>
        /// Gets/sets the duration in seconds for which this token is valid. A value of EndTime
        /// </summary>
        private long _window;
        public long Window
        {
            get => _window;
            set
            {
                if (value < 0)
                    throw new ArgumentOutOfRangeException(nameof(value), "Value should be greater than 0");
                
                _window = value;
            }
        }

        public string ExpirationField
        {
            get
            {
                if (Window == 0 && EndTime == 0)
                {
                    throw new Exception("A valid value for either 'Window' or 'EndTime' is required");
                }
                if (EndTime > 0 && EndTime <= StartTime)
                {
                    throw new Exception("Value of 'EndTime' should be greater than 'StartTime'");
                }

                return EndTime == 0
                    ? $"exp={(StartTime == 0 ? UnixTimeProvider.GetUnixTimeSeconds() : StartTime) + Window}{FieldDelimiter}"
                    : $"exp={EndTime}{FieldDelimiter}";
            }
        }

        /// <summary>
        /// The access control list for which the token is valid. Example: /*
        /// </summary>
        public string Acl { get; set; }

        public string AclField
        {
            get
            {
                if (string.IsNullOrEmpty(Acl))
                    throw new Exception("A valid value for 'Acl' is required");

                return PreEscapeAcl
                        ? $"acl={Uri.EscapeDataString(Acl).Replace(",", "%2c").Replace("*", "%2a")}{FieldDelimiter}"
                        : $"acl={Acl}{FieldDelimiter}";
            }
        }

        /// <summary>
        /// The session identifier for single use tokens or other advanced cases
        /// </summary>
        public string SessionId { get; set; }

        public string SessionIdField => string.IsNullOrEmpty(SessionId) ? string.Empty : $"id={SessionId}{FieldDelimiter}";

        /// <summary>
        /// Additional text added to the calculated token digest
        /// </summary>
        public string Payload { get; set; }

        public string PayloadField => string.IsNullOrEmpty(Payload) ? string.Empty : $"data={Payload}{FieldDelimiter}";

        /// <summary>
        /// Secret required to generate the token
        /// </summary>
        private string _key;
        public string Key
        {
            get => _key;
            set
            {
                if (string.IsNullOrEmpty(value) || ((value.Length & 1) == 1) || !KeyRegex.IsMatch(value))
                    throw new ArgumentException("Key should be an even length alpha-numeric string", nameof(value));

                _key = value;
            }
        }

        /// <summary>
        /// Character used to delimit token body fields.
        /// </summary>
        public char FieldDelimiter { get; set; }

        public override string ToString()
        {
            return string.Format(@"Config:{0}\t"
                + "Algo:{1}{0}"
                + "IpField:{2}{0}"
                + "StartTimeField:{3}{0}"
                + "Window:{4}{0}"
                + "ExpirationField:{5}{0}"
                + "AclField:{6}{0}"
                + "SessionIdField:{7}{0}"
                + "PayloadField:{8}{0}"
                + "Key:{9}{0}"
                + "FieldDelimiter:{10}{0}",
                Environment.NewLine,
                TokenAlgorithm,
                IpField,
                StartTimeField,
                Window,
                ExpirationField,
                AclField,
                SessionIdField,
                PayloadField,
                Key,
                FieldDelimiter);
        }
    }
}
