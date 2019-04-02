using System;
using System.Security.Cryptography;
using System.Text;

namespace BookBeat.Akamai.EdgeAuthToken
{
    public interface IAkamaiTokenGenerator
    {
        /// <summary>
        /// Generates a token
        /// </summary>
        /// <param name="tokenConfig">Configuration values to create token</param>
        /// <returns></returns>
        string GenerateToken(IAkamaiTokenConfig tokenConfig);
    }

    /// <summary>
    /// Token generator
    /// </summary>
    public class AkamaiTokenGenerator : IAkamaiTokenGenerator
    {
        /// <summary>
        /// Generates a token
        /// </summary>
        /// <param name="tokenConfig">Configuration values to create token</param>
        /// <returns></returns>
        public string GenerateToken(IAkamaiTokenConfig tokenConfig)
        {
            var tokenValues = tokenConfig.IpField + tokenConfig.StartTimeField
                + tokenConfig.ExpirationField + tokenConfig.AclField
                + tokenConfig.SessionIdField + tokenConfig.PayloadField;

            var hmac = CalculateHMAC(tokenValues.TrimEnd(tokenConfig.FieldDelimiter), tokenConfig.Key, tokenConfig.TokenAlgorithm);

            return tokenConfig.PreEscapeAcl
                ? $"{tokenValues}hmac={hmac}"
                : Uri.EscapeUriString($"{tokenValues}hmac={hmac}");
        }

        private string CalculateHMAC(string data, string key, Algorithm algorithm)
        {
            var sb = new StringBuilder();
            try
            {
                var hmac = HMAC.Create(algorithm.ToString());
                hmac.Key = HexStringToByteConverter.ToByteArray(key);

                // compute hmac
                var rawHmac = hmac.ComputeHash(Encoding.ASCII.GetBytes(data));

                // convert to hex string
                foreach (var b in rawHmac)
                {
                    sb.AppendFormat("{0:x2}", b);
                }
            }
            catch (Exception ex)
            {
                throw new Exception("Failed to create token", ex);
            }

            return sb.ToString();
        }
    }
}