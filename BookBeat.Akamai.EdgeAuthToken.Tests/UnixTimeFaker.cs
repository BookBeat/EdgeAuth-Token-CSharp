using System;

namespace BookBeat.Akamai.EdgeAuthToken.Tests
{
    public class UnixTimeFaker : IUnixTimeProvider
    {
        private DateTimeOffset _date;

        public UnixTimeFaker(DateTimeOffset date)
        {
            _date = date;
        }

        public long GetUnixTimeSeconds()
        {
            return _date.ToUnixTimeSeconds();
        }
    }
}
