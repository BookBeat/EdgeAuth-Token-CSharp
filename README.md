# EdgeAuth-Token-CSharp: Akamai Edge Authorization Token Generator for C#
[![Build status](https://ci.appveyor.com/api/projects/status/6kut5wktspt8nhf5/branch/master?svg=true)](https://ci.appveyor.com/project/NiklasArbin/knightbus/branch/master) 
[![NuGet](https://img.shields.io/nuget/v/BookBeat.Akamai.EdgeAuthToken.svg)](https://github.com/BookBeat/EdgeAuth-Token-CSharp/)

EdgeAuth-Token-CSharp is an Akamai Edge Authorization Token generator library for .Net Standard. Test Project runs on .Net Core. 
You can set up and configure token authorization in the Akamai Property Manager at https://control.akamai.com. 
Add behavior "Auth Token 2.0 Verification" to your property to get started.

![alt text](https://github.com/AstinCHOI/akamai-asset/blob/master/edgeauth/edgeauth.png?raw=true "Akamai EdgeAuth Token Config")

Further documentation available here: 
https://learn.akamai.com/en-us/webhelp/adaptive-media-delivery/adaptive-media-delivery-implementation-guide/GUID-041AEFDE-7E25-4AD8-B6C4-73F1B7200F02.html

### Installation
To Install Akamai Edge Authorization Token NuGet Package:  
```
Install-Package BookBeat.Akamai.EdgeAuthToken
```

### Example
```csharp
using BookBeat.Akamai.EdgeAuthToken;

namespace MyNamespace
{
    class MyTokenGenerator
    {
        public string GenerateMyToken(long startTime, long window, string acl, string key)
        {
            var tokenConfig = new AkamaiTokenConfig
            {
                StartTime = startTime, // Value in Unix time seconds. Defaults to DateTimeOffset.Now.ToUnixTimeSeconds()
                Window = window, // Time to live
                Acl = acl, // The access control list for which the token is valid
                Key = key // Your key
            };

            var tokenGenerator = new AkamaiTokenGenerator();

            var token = tokenGenerator.GenerateToken(tokenConfig);

            return token;
        }
    }
}
```

### License
Copyright (c) 2013, Akamai Technologies, Inc.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer 
      in the documentation and/or other materials provided with the distribution.
    * Neither the name of Akamai Technologies nor the names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, 
BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL AKAMAI TECHNOLOGIES BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; 
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.