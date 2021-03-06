using System;
using NUnit.Framework;

namespace BookBeat.Akamai.EdgeAuthToken.Tests
{
    public class EdgeAuthTokenTests
    {
        private IAkamaiTokenGenerator _tokenGenerator;
        private IAkamaiTokenConfig _tokenConfig;

        [SetUp]
        public void Setup()
        {
            _tokenGenerator = new AkamaiTokenGenerator();
            _tokenConfig = new AkamaiTokenConfig { UnixTimeProvider = new UnixTimeFaker(DateTimeOffset.Now) };
        }

        [TestCase(1294788122, 86400, "/*", "abc123")]
        [TestCase(1000, 1000, "/api/", "123abc")]
        public void GetBasicTokenWithAcl_ExpectCorrectParams(long startTime, long window, string acl, string key)
        {
            // Arrange 
            _tokenConfig = new AkamaiTokenConfig
            {
                StartTime = startTime,
                Window = window,
                Acl = acl,
                Key = key
            };

            // Act
            var token = _tokenGenerator.GenerateToken(_tokenConfig);

            // Assert
            var expectedParams = $"st={_tokenConfig.StartTime}~exp={_tokenConfig.StartTime + _tokenConfig.Window}~acl={_tokenConfig.Acl}~";
            var actualParams = token.Substring(0, token.IndexOf("hmac=", StringComparison.InvariantCulture));
            var hmac = token.Substring(token.IndexOf("hmac=", StringComparison.InvariantCulture) + "hmac=".Length);

            Assert.AreEqual(expectedParams, actualParams);
            Assert.IsTrue(hmac.Length > 0);
        }

        [Test]
        public void GetBasicTokenWithNoStartTime_ExpectCorrectParams()
        {
            // Arrange 
            _tokenConfig = new AkamaiTokenConfig
            {
                Window = 600,
                Acl = "/*",
                Key = "key123"
            };

            // Act
            var token = _tokenGenerator.GenerateToken(_tokenConfig);

            // Assert
            var expectedParams = $"exp={_tokenConfig.UnixTimeProvider.GetUnixTimeSeconds() + _tokenConfig.Window}~acl={_tokenConfig.Acl}~";
            var actualParams = token.Substring(0, token.IndexOf("hmac=", StringComparison.InvariantCulture));
            var hmac = token.Substring(token.IndexOf("hmac=", StringComparison.InvariantCulture) + "hmac=".Length);

            Assert.AreEqual(expectedParams, actualParams);
            Assert.IsTrue(hmac.Length > 0);
        }

        [Test]
        public void InstantiateConfigWithNoStartTime_VerifyExpiryFieldHasValue()
        {
            // Arrange / Act
            _tokenConfig = new AkamaiTokenConfig
            {
                TokenAlgorithm = Algorithm.HMACSHA256,
                Window = 300,
                Acl = "/*",
                Key = "abc123"
            };

            // Assert
            var startIndex = _tokenConfig.ExpirationField.IndexOf('=', StringComparison.InvariantCulture) + 1;
            var lastIndex = _tokenConfig.ExpirationField.IndexOf('~', StringComparison.InvariantCulture);
            var expiryTime = long.Parse(_tokenConfig.ExpirationField.Substring(startIndex, lastIndex - startIndex));
            
            Assert.AreEqual(string.Empty, _tokenConfig.StartTimeField);
            Assert.AreEqual(expiryTime, _tokenConfig.UnixTimeProvider.GetUnixTimeSeconds() +_tokenConfig.Window);
        }

        [Test]
        public void GetTokenWithBothEndTimeAndWindow_ExpectEndTimeToBeUsed()
        {
            // Arrange
            _tokenConfig = new AkamaiTokenConfig
            {
                TokenAlgorithm = Algorithm.HMACSHA256,
                StartTime = 1,
                Window = 100,
                EndTime = 200,
                Key = "ab09",
                Acl = "/*"
            };

            // Act
            var token = _tokenGenerator.GenerateToken(_tokenConfig);

            // Assert
            var expectedParams = $"st={_tokenConfig.StartTime}~exp={_tokenConfig.EndTime}~acl={_tokenConfig.Acl}~";
            var actualParams = token.Substring(0, token.IndexOf("hmac=", StringComparison.InvariantCulture));

            Assert.AreEqual(expectedParams, actualParams);
        }

        [Test]
        public void GetTokenWithNoEndTimeOrWindow_ShouldThrow()
        {
            // Arrange / Act / Assert
            _tokenConfig = new AkamaiTokenConfig
            {
                Key = "abc123",
                Acl = "/*"
            };

            // Act / Assert
            Assert.That(() => _tokenGenerator.GenerateToken(_tokenConfig),
                Throws.TypeOf<Exception>().With.Message.EqualTo("A valid value for either 'Window' or 'EndTime' is required"));
        }

        [Test]
        public void CreateConfigWithInvalidEndTime_ShouldThrow()
        {
            // Arrange / Act / Assert
            Assert.That(() => _tokenConfig = new AkamaiTokenConfig
            {
                Key = "abc123",
                Acl = "/*",
                EndTime = -1
            }, Throws.TypeOf<ArgumentOutOfRangeException>().With.Message.EqualTo("Value should be greater than 0\r\nParameter name: value"));
        }

        [Test]
        public void CreateConfigWithInvalidWindow_ShouldThrow()
        {
            // Arrange / Act / Assert
            Assert.That(() => _tokenConfig = new AkamaiTokenConfig
            {
                Key = "abc123",
                Acl = "/*",
                Window = -1
            }, Throws.TypeOf<ArgumentOutOfRangeException>().With.Message.EqualTo("Value should be greater than 0\r\nParameter name: value"));
        }

        [TestCase("a")] // Invalid length 
        [TestCase("ab1")] // Invalid length 
        [TestCase("a&")] // Non alphanum key
        [TestCase("")]
        [TestCase(null)]
        public void CreateConfigWithInvalidKey_ShouldThrow(string key)
        {
            // Arrange / Act / Assert
            Assert.That(() => _tokenConfig = new AkamaiTokenConfig
            {
                TokenAlgorithm = Algorithm.HMACSHA256,
                Window = 300,
                Acl = "/*",
                Key = key
            }, Throws.TypeOf<ArgumentException>().
                With.Message.EqualTo("Key should be an even length alpha-numeric string\r\nParameter name: value"));
        }

        [TestCase("")]
        [TestCase(null)]
        public void GenerateTokenWithEmptyAcl_ShouldThrow(string acl)
        {
            // Arrange / Act
            _tokenConfig = new AkamaiTokenConfig
            {
                TokenAlgorithm = Algorithm.HMACSHA256,
                Window = 300,
                Acl = acl,
                Key = "abc123"
            };

            // Assert
            Assert.That(() => _tokenGenerator.GenerateToken(_tokenConfig),
                Throws.TypeOf<Exception>().With.Message.EqualTo("A valid value for 'Acl' is required"));
        }
    }
}