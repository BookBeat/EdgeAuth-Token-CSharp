using System;

namespace BookBeat.Akamai.EdgeAuthToken
{
    public interface IUnixTimeProvider
    {
        long GetUnixTimeSeconds();
    }

    public class UnixTimeProvider : IUnixTimeProvider
    {
        public long GetUnixTimeSeconds()
        {
            return DateTimeOffset.Now.ToUnixTimeSeconds();
        }
    }
}
